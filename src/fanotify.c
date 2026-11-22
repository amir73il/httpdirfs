#include "cache.h"
#include "link.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/fanotify.h>

/*
 * fanotify mode: lazy populate of the cache data dir.
 *
 * The cache data dir is bind mounted at the mountpoint and mount marks on the
 * bind mount request permission events for access by users.  httpdirfs itself
 * accesses the cache data dir via its original path, which is not watched, and
 * writes file data via the event fd, which does not generate events.
 *
 * - FAN_ACCESS_PERM on a directory (readdir) creates the cache entries of all
 *   the directory children.
 * - FAN_PRE_ACCESS on a file downloads the accessed range before the access.
 *
 * Pre-content events do not support event flags (FAN_ONDIR), not even in the
 * combined mask of a mark, so the two events are watched by two groups:
 * a FAN_CLASS_CONTENT group for directories and a FAN_CLASS_PRE_CONTENT group
 * for files.
 *
 * Fully populated objects get an evictable ignore mark, so they generate no
 * more events until their inode is evicted.
 *
 * Requires kernel v6.14 (FAN_PRE_ACCESS) and a cache dir on a filesystem that
 * supports pre-content events (ext4, xfs, btrfs).
 */

#ifndef FAN_PRE_ACCESS
#define FAN_PRE_ACCESS		0x00100000
#endif
#ifndef FAN_MARK_EVICTABLE
#define FAN_MARK_EVICTABLE	0x00000200
#endif
#ifndef FAN_MARK_IGNORE
#define FAN_MARK_IGNORE		0x00000400
#endif
#ifndef FAN_MARK_IGNORE_SURV
#define FAN_MARK_IGNORE_SURV	(FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY)
#endif
#ifndef FAN_DENY_ERRNO
#define FAN_ERRNO(err)		(((((__u32)(err)) & 0xff) << 24))
#define FAN_DENY_ERRNO(err)	(FAN_DENY | FAN_ERRNO(err))
#endif
#ifndef FAN_EVENT_INFO_TYPE_RANGE
#define FAN_EVENT_INFO_TYPE_RANGE	6
#endif

/* struct fanotify_event_info_range (since v6.14), for older headers */
struct fan_event_info_range {
	struct fanotify_event_info_header hdr;
	__u32 pad;
	__u64 offset;
	__u64 count;
};

#define FAN_DIR_EVENTS	(FAN_ACCESS_PERM | FAN_ONDIR)
#define FAN_FILE_EVENTS	FAN_PRE_ACCESS

/* Group for directory access and group for file content access */
enum { DIR_GROUP, FILE_GROUP, NR_GROUPS };
static int fanotify_fds[NR_GROUPS] = { -1, -1 };
static const char *MNT_DIR;
static size_t MNT_DIR_len;
static int mounted;

static void fanotify_cleanup(int sig)
{
	if (mounted && umount2(MNT_DIR, MNT_DETACH))
		perror("umount");
	mounted = 0;

	if (sig)
		exit_error("Terminated by signal");
}

static void set_signal_handler(int sig, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, NULL))
		exit_perror("sigaction");
}

/* Stop getting events for a populated object, until its inode is evicted */
static void fanotify_ignore(int group, int fd, uint64_t mask,
			    const char *path)
{
	if (fanotify_mark(fanotify_fds[group],
			  FAN_MARK_ADD | FAN_MARK_IGNORE_SURV | FAN_MARK_EVICTABLE,
			  mask, fd, NULL)) {
		lprintf(warning, "Failed to ignore events on '%s' (%s)\n",
			path, strerror(errno));
	} else {
		lprintf(debug, "Ignoring events on '%s'\n", path);
	}
}

/*
 * Create the cache entries of all the children of the directory at path,
 * unless they already exist and are valid.
 */
static int fs_readdir(const char *path)
{
	char childpath[PATH_MAX];
	LinkTable *linktbl;
	size_t pathlen = strlen(path);

	if (!strcmp(path, "/"))
		linktbl = ROOT_LINK_TBL;
	else
		linktbl = path_to_Link_LinkTable_new(path);
	if (!linktbl)
		return -ENOENT;

	if (pathlen >= PATH_MAX - 2)
		return -ENAMETOOLONG;
	strcpy(childpath, path);
	if (childpath[pathlen - 1] != '/')
		childpath[pathlen++] = '/';
	childpath[pathlen] = 0;

	/* We skip the head link */
	for (int i = 1; i < linktbl->num; i++) {
		Link *link = linktbl->links[i];
		Cache *cache;

		snprintf(childpath + pathlen, PATH_MAX - pathlen, "%s",
			 link->linkname);
		switch (link->type) {
		case LINK_DIR:
			CacheDir_create(childpath);
			break;
		case LINK_FILE:
			cache = Cache_open(childpath);
			if (cache) {
				Cache_close(cache);
				break;
			}
			if (Cache_create(childpath))
				lprintf(warning, "Failed to create cache for '%s'\n",
					childpath);
			break;
		default:
			break;
		}
	}

	return 0;
}

/*
 * Download the range [offset, offset + count) of the file at path, writing it
 * via data_fd.
 *
 * Return values:
 * <0 to deny access and return error
 * >0 allow access but keep watching
 *  0 allow access and stop watching (fully cached)
 */
static int fs_read(const char *path, int data_fd, off_t offset, off_t count)
{
	Cache *cache = Cache_open_fd(path, data_fd);
	long ret;

	if (!cache) {
		/* The cache cannot be opened, attempt cache reset */
		if (!path_to_Link(path) || Cache_create(path))
			return -EIO;
		cache = Cache_open_fd(path, data_fd);
		if (!cache)
			return -EIO;
	}

	ret = Cache_populate(cache, offset, count);
	if (ret >= 0)
		ret = !Cache_complete(cache);

	Cache_close(cache);
	return ret;
}

static const struct fan_event_info_range *
event_range(const struct fanotify_event_metadata *event)
{
	const char *rec = (const char *)event + event->metadata_len;
	const char *end = (const char *)event + event->event_len;

	while (rec + sizeof(struct fanotify_event_info_header) <= end) {
		const struct fanotify_event_info_header *hdr = (const void *)rec;

		if (!hdr->len || rec + hdr->len > end)
			break;
		if (hdr->info_type == FAN_EVENT_INFO_TYPE_RANGE &&
		    hdr->len >= sizeof(struct fan_event_info_range))
			return (const void *)rec;
		rec += hdr->len;
	}
	return NULL;
}

/* Return a path relative to the mountpoint, starting with '/' */
static const char *event_path(int fd, char *buf, size_t size)
{
	char procfd_path[64];
	ssize_t len;

	snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", fd);
	len = readlink(procfd_path, buf, size - 1);
	if (len < 0)
		return NULL;
	buf[len] = 0;

	if ((size_t)len < MNT_DIR_len || strncmp(buf, MNT_DIR, MNT_DIR_len) ||
	    (buf[MNT_DIR_len] && buf[MNT_DIR_len] != '/'))
		return NULL;

	return buf[MNT_DIR_len] ? buf + MNT_DIR_len : "/";
}

static int handle_event(int group, const struct fanotify_event_metadata *event)
{
	char buf[PATH_MAX];
	const char *path = event_path(event->fd, buf, sizeof(buf));
	struct stat st;
	int ret;

	if (!path) {
		lprintf(warning, "Event on unexpected path '%s'\n", buf);
		return -EPERM;
	}
	if (fstat(event->fd, &st))
		return -EIO;

	if (group == DIR_GROUP) {
		if (!S_ISDIR(st.st_mode)) {
			/* The dir group has no interest in file access */
			fanotify_ignore(group, event->fd, FAN_ACCESS_PERM, path);
			return 0;
		}
		lprintf(debug, "readdir '%s'\n", path);
		ret = fs_readdir(path);
		if (!ret)
			fanotify_ignore(group, event->fd, FAN_DIR_EVENTS, path);
		return ret;
	}

	if (!S_ISREG(st.st_mode))
		return 0;

	const struct fan_event_info_range *range = event_range(event);
	off_t offset = range ? (off_t)range->offset : 0;
	off_t count = range ? (off_t)range->count : 0;

	lprintf(debug, "access '%s' [%lld@%lld]\n", path,
		(long long)count, (long long)offset);

	if (!st.st_size) {
		ret = 0;
	} else {
		ret = fs_read(path, event->fd, offset, count);
		if (ret < 0)
			return ret;
	}
	if (!ret)
		fanotify_ignore(group, event->fd, FAN_FILE_EVENTS, path);
	return 0;
}

static void handle_events(int group)
{
	int fanotify_fd = fanotify_fds[group];
	char buf[8192] __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
	const struct fanotify_event_metadata *event;
	ssize_t len;

	len = read(fanotify_fd, buf, sizeof(buf));
	if (len < 0) {
		if (errno == EINTR)
			return;
		exit_perror("read fanotify events");
	}

	for (event = (void *)buf; FAN_EVENT_OK(event, len);
	     event = FAN_EVENT_NEXT(event, len)) {
		struct fanotify_response response;
		int ret;

		if (event->vers != FANOTIFY_METADATA_VERSION)
			exit_error("Unexpected fanotify metadata version");
		if (event->fd < 0)
			continue;

		ret = handle_event(group, event);

		response.fd = event->fd;
		response.response = ret < 0 ? FAN_DENY_ERRNO(-ret) : FAN_ALLOW;
		if (write(fanotify_fd, &response, sizeof(response)) !=
		    sizeof(response))
			lprintf(error, "Failed to write response (%s)\n",
				strerror(errno));
		close(event->fd);
	}
}

int fanotify_main(const char *mountpoint)
{
	MNT_DIR = realpath(mountpoint, NULL);
	if (!MNT_DIR)
		exit_perror(mountpoint);
	MNT_DIR_len = strlen(MNT_DIR);

	fanotify_fds[DIR_GROUP] = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
						O_RDONLY | O_LARGEFILE);
	if (fanotify_fds[DIR_GROUP] < 0)
		exit_perror("fanotify_init");

	/* File data is written via the fds of pre-content events */
	fanotify_fds[FILE_GROUP] = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC,
						 O_RDWR | O_LARGEFILE);
	if (fanotify_fds[FILE_GROUP] < 0)
		exit_perror("fanotify_init pre-content (kernel >= v6.14 required)");

	set_signal_handler(SIGINT, fanotify_cleanup);
	set_signal_handler(SIGTERM, fanotify_cleanup);

	if (mount(DATA_DIR, MNT_DIR, NULL, MS_BIND, NULL))
		exit_perror("bind mount cache data dir");
	mounted = 1;

	if (fanotify_mark(fanotify_fds[FILE_GROUP], FAN_MARK_ADD | FAN_MARK_MOUNT,
			  FAN_FILE_EVENTS, AT_FDCWD, MNT_DIR) ||
	    fanotify_mark(fanotify_fds[DIR_GROUP], FAN_MARK_ADD | FAN_MARK_MOUNT,
			  FAN_DIR_EVENTS, AT_FDCWD, MNT_DIR)) {
		int err = errno;

		fanotify_cleanup(0);
		errno = err;
		exit_perror("fanotify_mark (does the cache fs support pre-content events?)");
	}

	lprintf(info, "Cache data dir '%s' is mounted at '%s'\n", DATA_DIR, MNT_DIR);

	for (;;) {
		struct pollfd fds[NR_GROUPS] = {
			{ .fd = fanotify_fds[DIR_GROUP], .events = POLLIN },
			{ .fd = fanotify_fds[FILE_GROUP], .events = POLLIN },
		};

		if (poll(fds, NR_GROUPS, -1) < 0) {
			if (errno == EINTR)
				continue;
			exit_perror("poll");
		}
		for (int group = 0; group < NR_GROUPS; group++) {
			if (fds[group].revents & POLLIN)
				handle_events(group);
		}
	}

	return 0;
}
