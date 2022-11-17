#include "link.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/fanotify.h>

#ifndef FAN_CLASS_VFS_FILTER
#define FAN_CLASS_VFS_FILTER 0x0000000c
#endif
#ifndef FAN_XATTR_IGNORE_MASK
#define FAN_XATTR_IGNORE_MASK 0x10000000
#endif
#ifndef FAN_REPORT_ACCESS_RANGE
#define FAN_REPORT_ACCESS_RANGE 0x00002000
#endif
#ifndef FAN_XATTR_IGNORE_MASK
#define FAN_XATTR_IGNORE_MASK 0x10000000
#endif

#define FAN_INIT_FLAGS (FAN_CLASS_VFS_FILTER | FAN_REPORT_ACCESS_RANGE)
#define FAN_INIT_XATTR_FLAGS (FAN_INIT_FLAGS | FAN_XATTR_IGNORE_MASK)

#ifndef FAN_MARK_EVICTABLE
#define FAN_MARK_EVICTABLE 0x00000200
#endif
#ifndef FAN_MARK_IGNORE
#define FAN_MARK_IGNORE 0x00000400
#endif
#ifndef FAN_MARK_SYNC
#define FAN_MARK_SYNC	0x00000800
#endif
#ifndef FAN_MARK_XATTR
#define FAN_MARK_XATTR  0x00001000
#endif
#ifndef FAN_MARK_IGNORE_SURV
#define FAN_MARK_IGNORE_SURV (FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY)
#endif

#ifndef FAN_LOOKUP_PERM
#define FAN_LOOKUP_PERM	0x00080000 /* Path lookup hook */
#endif

#ifndef FAN_PRE_MODIFY
#define FAN_PRE_MODIFY	0x00100000 /* Pre data modify */
#endif
#ifndef FAN_PRE_ATTRIB
#define FAN_PRE_ATTRIB	0x00200000 /* Pre metadata change */
#endif
#define FAN_PRE_DIRENT	0x03c00000 /* Pre create/delete/move */

#ifndef FAN_PRE_VFS
#define FAN_PRE_VFS	0x80000000 /* Pre-vfs filter hook */
#endif


#define FAN_PRE_ACCESS	(FAN_ACCESS_PERM | FAN_LOOKUP_PERM | FAN_PRE_MODIFY)
#define FAN_PRE_CHANGE	(FAN_PRE_ATTRIB | FAN_PRE_MODIFY)
#define FAN_EVENTS	(FAN_OPEN_PERM | FAN_PRE_ACCESS | FAN_PRE_CHANGE | \
			 FAN_PRE_DIRENT | FAN_PRE_VFS)

#ifndef FAN_EVENT_INFO_TYPE_RANGE
#define FAN_EVENT_INFO_TYPE_RANGE 6

struct fanotify_event_info_range {
	struct fanotify_event_info_header hdr;
	__u32 count;
	__u64 offset;
};
#endif

#ifndef FAN_ERRNO
#define FAN_ERRNO	0x03

struct fanotify_response_error {
	__s32 fd;
	__u32 response  :16,
	      error     :8,
	      reserved  :8;
};
#endif

struct fanotify_group {
	int fd;
	uint64_t mask;
	const char *name;
	int ignore_mark_flags;
};

/* After this call, future open syscalls are denied by the mark mount */
static int fanotify_reset_data_watch(struct fanotify_group *fanotify,
				     const char *path)
{
	/* Remove inode mark with ignore mask to start getting open/access events */
	int flags = FAN_MARK_REMOVE | fanotify->ignore_mark_flags;
	uint64_t mask = FAN_OPEN_PERM | FAN_PRE_ACCESS;

	if (fanotify_mark(fanotify->fd, flags, mask,
			  DATA_DIR_fd, path) && errno != ENOENT) {
		lprintf(warning, "Failed reseting watch on '%s' (%s)\n",
			path, strerror(errno));
		return -1;
	}

	lprintf(info, "Reset access watch on '%s'\n", path);
	return 0;
}

/* After this call, future open syscalls are allowed */
static int fanotify_add_data_watch(struct fanotify_group *fanotify,
				   const char *path, int is_dir)
{
	/* Add inode mark with ignore mask to stop getting open events */
	int flags = FAN_MARK_ADD | fanotify->ignore_mark_flags;
	uint64_t mask = FAN_OPEN_PERM | (is_dir ? FAN_ONDIR : 0);

	if (fanotify_mark(fanotify->fd, flags, mask,
			  DATA_DIR_fd, path)) {
		lprintf(warning, "Failed adding watch on '%s' (%s)\n",
			path, strerror(errno));
		return -1;
	}

	lprintf(info, "Added access watch on '%s'\n", path);
	return 0;
}

static void fanotify_remove_data_watch(struct fanotify_group *fanotify,
				       const char *path, int is_dir)
{
	/* Add inode mark with ignore mask to stop getting access/change events */
	int flags = FAN_MARK_ADD | fanotify->ignore_mark_flags;
	uint64_t mask = fanotify->mask | (is_dir ? FAN_ONDIR : 0);

	if (fanotify_mark(fanotify->fd, flags, mask,
			  DATA_DIR_fd, path)) {
		lprintf(warning, "Failed removing watch on '%s' (%s)\n",
			path, strerror(errno));
		return;
	}

	lprintf(info, "Removed %s watch on '%s'\n", fanotify->name, path);
}

static void fanotify_add_root_watch(struct fanotify_group *fanotify,
				    const char *path)
{
	/* Ignore open of data root dir before denying all opens on mount/fs */
	fanotify_add_data_watch(fanotify, ".", 1);

	if (fanotify_mark(fanotify->fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			  FAN_OPEN_PERM | FAN_PRE_ACCESS | FAN_PRE_VFS | FAN_ONDIR,
			  AT_FDCWD, path))
		exit_perror("add data access root mark");

	fanotify++;
	if (fanotify_mark(fanotify->fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			  FAN_PRE_CHANGE | FAN_PRE_DIRENT | FAN_PRE_VFS | FAN_ONDIR,
			  AT_FDCWD, path))
		exit_perror("add change tracking root mark");

	lprintf(info, "Added mount watch on '%s'\n", path);
}

static int fs_init_cache(struct fanotify_group *fanotify, const char *path,
			 int is_dir)
{
	int ret;

	ret = is_dir ? CacheDir_create(path) : Cache_create(path, 0);
	if (ret < 0)
		return ret;

	/* Allow open and watch for data access */
	return fanotify_add_data_watch(fanotify, path, is_dir);
}

static int fs_readdir(struct fanotify_group *fanotify, const char *path)
{
	size_t pathlen = strlen(path);
	char childpath[PATH_MAX];
	LinkTable *linktbl;
	int ret = 0;

	if (!pathlen)
		return -EINVAL;

	if (!strcmp(path, ".")) {
		linktbl = ROOT_LINK_TBL;
	} else {
		linktbl = path_to_Link_LinkTable_new(path);
		if (!linktbl) {
			return -ENOENT;
		}
	}

	strcpy(childpath, path);
	childpath[pathlen++] = '/';

	/* We skip the head link */
	for (int i = 1; i < linktbl->num; i++) {
		Link *link = linktbl->links[i];
		switch (link->type) {
			case LINK_DIR:
				sprintf(childpath + pathlen, "%s/", link->linkname);
				break;
			case LINK_FILE:
				sprintf(childpath + pathlen, "%s", link->linkname);
				break;
			default:
				continue;
		}
		ret = fs_init_cache(fanotify, childpath, link->type == LINK_DIR);
		if (ret)
			break;
	}

	return ret;
}

static int fs_read(const char *path, int data_fd, off_t offset, size_t size)
{
	Link *link = path_to_Link(path);
	if (!link)
		return -ENOENT;

	/* Use the fd provided by fanotify to write to cache data file
	 * to avoid deadlocks */
	Cache *cache = Cache_open(path, data_fd);
	if (!cache) {
		/*
		 * The link clearly exists, the cache cannot be opened,
		 * attempt cache reset.
		 */
		Cache_create(path, 1);
		cache = Cache_open(path, data_fd);
		/*
		 * The cache definitely cannot be opened for some reason.
		 */
		if (!cache)
			return -ENOENT;
	}

	/* Read via cache into "/dev/null" to populate cache */
	long recv = Cache_read(cache, NULL, size, offset);

	Cache_close(cache);

	return recv;
}

/*
 * Return values:
 * <0 to deny access and return error
 * >0 allow access but keep watching
 *  0 allow access and stop watching
 */
static int handle_access_event(struct fanotify_group *fanotify,
			       const struct fanotify_event_metadata *event,
			       const char *relpath, struct stat *st,
			       off_t offset, size_t size)
{
	int ret;

	if (!(event->mask & FAN_PRE_VFS)) {
		/* Writing to cache is not allowed */
		/* TODO: read-only check if cache is already populated */
		return -EPERM;
	}

	switch (st->st_mode & S_IFMT) {
		case S_IFDIR:
			/* Allow dir to be accessed if all cache entries are created */
			/* TODO: populate a single child entry on FAN_LOOKUP_PERM event */
			ret = fs_readdir(fanotify, relpath);
			break;
		case S_IFREG:
			/* Allow file to be accessed if the requested range was downloaded */
			/* Request at least 1 byte, so return 0 will mean fully downloaded */
			ret = fs_read(relpath, event->fd, offset, size ?: 1);
			break;
		default:
			ret = -EPERM;
	}

	/* Deny modify content and truncate if cache is not fully populated */
	if (ret > 0 && event->mask & FAN_PRE_MODIFY)
		ret = -EROFS;

	return ret;
}

/*
 * Return values:
 * <0 to deny change and return error
 * >0 allow change but keep watching
 *  0 allow change and stop watching
 */
static int handle_change_event(struct fanotify_group *fanotify,
			       const struct fanotify_event_metadata *event,
			       const char *relpath, struct stat *st)
{
	/* Deny change if change is not recorded */
	return -EROFS;
}

static void handle_events(struct fanotify_group *fanotify)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[200];
	off_t offset;
	size_t count;
	ssize_t len;
	char abspath[PATH_MAX];
	const char *relpath;
	ssize_t path_len;
	char procfd_path[PATH_MAX];
	struct fanotify_response_error response;
	int ret;

	len = read(fanotify->fd, (void *) &buf, sizeof(buf));
	if (len <= 0 && errno != EINTR)
		exit_perror("read");

	metadata = buf;
	while (FAN_EVENT_OK(metadata, len)) {
		if (metadata->vers != FANOTIFY_METADATA_VERSION ||
		    metadata->fd < 0 || !(metadata->mask & FAN_EVENTS))
			exit_error("Unexpected fanotify event");

		/* Retrieve absolute path of the accessed file */
		snprintf(procfd_path, sizeof(procfd_path),
				"/proc/self/fd/%d", metadata->fd);
		path_len = readlink(procfd_path, abspath, sizeof(abspath) - 1);
		if (path_len == -1)
			exit_perror("readlink");

		abspath[path_len] = '\0';
		relpath = Data_relpath(metadata->fd, abspath);
		if (!relpath)
			exit_error("Unexpected path in event");

		/*
		 * Empty relative path meants event on data root dir -
		 * use relative path "." for syscalls that do not support
		 * AT_EMPTY_PATH.
		 */
		if (!*relpath)
			relpath = ".";

		struct stat st;
		if (fstat(metadata->fd, &st))
			exit_perror("fstat");

		/*
		 * If no range in event, setting offset to EOF will check if
		 * file is fully downloaded.
		 */
		offset = st.st_size;
		count = 0;
		if (metadata->event_len > FAN_EVENT_METADATA_LEN) {
			const struct fanotify_event_info_range *range;
			range = (const struct fanotify_event_info_range *)(metadata + 1);
			if (range->hdr.info_type == FAN_EVENT_INFO_TYPE_RANGE) {
				count = range->count;
				offset = range->offset;
			}
		}

		lprintf(debug, "Got event 0x%08x on '%s' (%s) [%d@%llu]\n",
			metadata->mask, abspath, relpath, count, offset);

		ret = -EPERM;
		if (!(fanotify->mask & metadata->mask)) {
			/* Deny FAN_PRE_DIRENT and open of file during eviction */
		} else if (fanotify->mask == FAN_PRE_ACCESS) {
			ret = handle_access_event(fanotify, metadata, relpath, &st,
						  offset, count);
		} else if (fanotify->mask == FAN_PRE_CHANGE) {
			ret = handle_change_event(fanotify, metadata, relpath, &st);
		}

		response.fd = metadata->fd;
		if (ret < 0) {
			response.response = FAN_ERRNO;
			response.error = -ret;
		} else {
			response.response = FAN_ALLOW;
			response.error = 0;
		}
		write(fanotify->fd, &response, sizeof(struct fanotify_response));
		if (!ret) {
			fanotify_remove_data_watch(fanotify, relpath,
						   st.st_mode & S_IFDIR);
		}
		close(metadata->fd);
		metadata = FAN_EVENT_NEXT(metadata, len);
	}
}

static void *events_loop(void *group)
{
	for (;;)
		handle_events(group);

	return NULL;
}

static int fanotify_bind_mounted;
static struct fanotify_group *fanotify_evict_group;
static const char *fanotify_evict_path;

static void fanotify_evict_cleanup(struct fanotify_group *fanotify, const char *path)
{
	fanotify_add_data_watch(fanotify, path, 0);
}

static void fanotify_mount_cleanup()
{
	if (CONFIG.mount_dir)
		umount(CONFIG.mount_dir);
	umount(DATA_DIR);
	umount(DATA_DIR);
}

static void fanotify_cleanup(int sig)
{
	(void) sig;	/* unused */

	if (fanotify_evict_path) {
		fanotify_evict_cleanup(fanotify_evict_group, fanotify_evict_path);
		exit_error("Evict file aborted by signal");
	}

	if (DATA_DIR_fd > 0)
		close(DATA_DIR_fd);

	if (fanotify_bind_mounted)
		fanotify_mount_cleanup();

	if (sig)
		exit_error("Terminated by signal");
	else
		exit_error("Quit by user");
}

static void set_signal_handler(int sig, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = handler;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;

	if (sigaction(sig, &sa, NULL))
		exit_perror("sigaction");
}

void fanotify_watch_data_dir(struct fanotify_group *fanotify)
{
	set_signal_handler(SIGINT, fanotify_cleanup);
	set_signal_handler(SIGTERM, fanotify_cleanup);

	/* Cleanup old mounts */
	fanotify_mount_cleanup();

	/*
	 * Create bind mount and move it to mount dir.
	 * We need to create a private parent bind mount from which
	 * the child mount can be moved.
	 */
	if (CONFIG.mount_dir &&
	    (mount(DATA_DIR, DATA_DIR, NULL, MS_BIND, NULL) ||
	     mount(NULL, DATA_DIR, NULL, MS_PRIVATE, NULL))) {
		fanotify_mount_cleanup();
		exit_perror("make-priavte mount data dir");
	}


	fanotify_bind_mounted = !mount(DATA_DIR, DATA_DIR, NULL, MS_BIND, NULL);
	if (!fanotify_bind_mounted) {
		fanotify_mount_cleanup();
		exit_perror("bind mount data dir");
	}

	/* Hook on any access to bind mount before moving into place */
	fanotify_add_root_watch(fanotify, DATA_DIR);

	if (CONFIG.mount_dir &&
	    mount(DATA_DIR, CONFIG.mount_dir, NULL, MS_MOVE, NULL)) {
		fanotify_mount_cleanup();
		exit_perror("move mount data dir");
	}
}

/********************************************/
/* Console commands                         */
/********************************************/

/*
 * Command to evict a file's cache
 */
static int evict_file(struct fanotify_group *fanotify, const char *path)
{
	const char *relpath = Data_relpath(AT_FDCWD, path);
	int ret = -1;

	if (!relpath) {
		lprintf(error, "Path '%s' is not cached\n", path);
		return -1;
	}

	/* Recover after aborted evict */
	fanotify_evict_cleanup(fanotify, relpath);

	/*
	 * Run in a forked process so evict can be aborted by lease breakers
	 */
	pid_t pid = fork();
	if (pid > 0)
		return wait(NULL) >= 0;
	else if (pid < 0)
		exit_perror("fork");

	fanotify_evict_group = fanotify;
	fanotify_evict_path = relpath;
	set_signal_handler(SIGIO, fanotify_cleanup);

	int fd = openat(DATA_DIR_fd, relpath, O_RDWR | O_NONBLOCK);
	if (fd < 0)
		exit_perror(path);

	struct stat st;
	if (fstat(fd, &st))
		exit_perror("fstat");

	if (!(st.st_mode & S_IFREG))
		exit_error("Only regular file cache can be evicted.");

	/*
	 * Acquire write lease to make sure no open fds.
	 */
	if (fcntl(fd, F_SETLEASE, F_WRLCK))
		exit_error("File is open and cannot be evicted.");

	if (fanotify_reset_data_watch(fanotify, relpath))
		exit_error("Failed denying opens.");

	lprintf(info, "Starting file '%s' cache eviction.\n", path);

	/*
	 * Now fanotify HSM will deny new opens.
	 * Reacquire write lease to make sure no opens in progress.
	 */
	if (fcntl(fd, F_SETLEASE, F_UNLCK) || fcntl(fd, F_SETLEASE, F_WRLCK)) {
		lprintf(warning, "File '%s' is open - cache eviction aborted!\n",
			path);
		goto out;
	}

	/* Reset cache entry by removing meta file and punching data file */
	Cache_delete(relpath, fd);

	lprintf(info, "File '%s' cache was evicted!\n", path);
	ret = 0;
out:
	fanotify_evict_cleanup(fanotify, relpath);
	close(fd);
	exit(ret);
}

void handle_command(struct fanotify_group *fanotify)
{
	static char *line = NULL;
	static size_t len = 0;
	ssize_t nread;

	nread = getline(&line, &len, stdin);
	if (nread <= 0)
		exit_perror("getline");
	line[nread - 1] = 0;

	switch (*line) {
		case '\0':
			return;
		case 'q':
			fanotify_cleanup(0);
			break;
		case 'e':
			if (nread > 7 && !strncmp(line, "evict ", 6)) {
				evict_file(fanotify, line + 6);
				return;
			}
			break;
	}

	lprintf(warning, "Unknown command: %s", line);
}

static int fanotify_init_group(struct fanotify_group *fanotify, const char *name,
				int init_flags, int mark_flags, uint64_t mask)
{
	int fd = fanotify_init(init_flags, O_RDWR | O_LARGEFILE);

	if (fd < 0)
		return fd;

	fanotify->fd = fd;
	fanotify->name = name;
	fanotify->mask = mask;
	fanotify->ignore_mark_flags = FAN_MARK_IGNORE_SURV | mark_flags;
	return 0;
}

int fanotify_main()
{
	struct fanotify_group fanotify[2];
	pthread_t access_monitor;
	pthread_t change_monitor;

	/* If persistent xattr marks not supported - fallback to evictable marks */
	if (fanotify_init_group(fanotify, "access", FAN_INIT_XATTR_FLAGS,
				FAN_MARK_XATTR, FAN_PRE_ACCESS) &&
	    fanotify_init_group(fanotify, "access", FAN_INIT_FLAGS,
				FAN_MARK_EVICTABLE, FAN_PRE_ACCESS))
		exit_perror("init fanotify (data access) group");

	if (fanotify_init_group(fanotify + 1, "change", FAN_INIT_FLAGS,
				FAN_MARK_EVICTABLE, FAN_PRE_CHANGE))
		exit_perror("init fanotify (change tracking) group");

	/* Watch events on data or mount dir */
	fanotify_watch_data_dir(fanotify);

	if (pthread_create(&access_monitor, NULL, events_loop, (void*)fanotify))
		exit_perror("start access monitor thread");
	if (pthread_create(&change_monitor, NULL, events_loop, (void*)(fanotify + 1)))
		exit_perror("start change monitor thread");

	for (;;)
		handle_command(fanotify);

	pthread_join(access_monitor, NULL);
	pthread_join(change_monitor, NULL);
	close(fanotify[0].fd);
	close(fanotify[1].fd);
	return 0;
}
