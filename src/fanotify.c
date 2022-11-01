#include "link.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/fanotify.h>

#ifndef FAN_XATTR_IGNORE_MASK
#define FAN_XATTR_IGNORE_MASK 0x00010000
#endif
#define FAN_INIT_XATTR_FLAGS (FAN_CLASS_PRE_CONTENT | FAN_XATTR_IGNORE_MASK)

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
#ifndef FAN_MODIFY_PERM
#define FAN_MODIFY_PERM	0x00100000 /* Pre data modify */
#endif
#ifndef FAN_ATTRIB_PERM
#define FAN_ATTRIB_PERM	0x00200000 /* Pre metadata change */
#endif
#define FAN_PRE_DIRENT	0x01c00000 /* create/delete/rename */

#define FAN_PRE_ACCESS	(FAN_ACCESS_PERM | FAN_LOOKUP_PERM | FAN_MODIFY_PERM)
#define FAN_EVENTS	(FAN_OPEN_PERM | FAN_PRE_ACCESS | FAN_PRE_DIRENT)

#ifndef FAN_DENY_ERROR
#define FAN_DENY_ERROR	0x03

struct fanotify_response_error {
	__s32 fd;
	__u32 response  :16,
	      error     :8,
	      reserved  :8;
};
#endif

static int ignore_mark_flags = FAN_MARK_IGNORE_SURV | FAN_MARK_XATTR;

static int fanotify_add_data_watch(int fanotify_fd, const char *path, int is_dir)
{
	/* Add inode mark with ignore mask to stop getting open events */
	uint64_t mask = FAN_OPEN_PERM | (is_dir ? FAN_ONDIR : 0);

	if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | ignore_mark_flags, mask,
			  DATA_DIR_fd, path)) {
		lprintf(warning, "Failed adding watch on '%s' (%s)\n",
			path, strerror(errno));
		return -1;
	}

	lprintf(info, "Added data watch on '%s'\n", path);
	return 0;
}

static void fanotify_remove_data_watch(int fanotify_fd, const char *path, int is_dir)
{
	/* Add inode mark with ignore mask to stop getting access events */
	uint64_t mask = FAN_PRE_ACCESS | (is_dir ? FAN_ONDIR : 0);

	if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | ignore_mark_flags, mask,
			  DATA_DIR_fd, path)) {
		lprintf(warning, "Failed removing watch on '%s' (%s)\n",
			path, strerror(errno));
		return;
	}

	lprintf(info, "Removed data watch on '%s'\n", path);
}

static void fanotify_add_root_watch(int fanotify_fd, const char *path)
{
	/* Ignore open of data root dir before denying all opens on mount/fs */
	fanotify_add_data_watch(fanotify_fd, ".", 1);

	if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			  FAN_EVENTS | FAN_ONDIR, AT_FDCWD, path))
		exit_perror("add data dir root mark");

	lprintf(info, "Added mount watch on '%s'\n", path);
}

static int fs_init_cache(int fanotify_fd, const char *path, int is_dir)
{
	int ret;

	ret = is_dir ? CacheDir_create(path) : Cache_create(path, 0);
	if (ret < 0)
		return ret;

	/* Allow open and watch for data access */
	return fanotify_add_data_watch(fanotify_fd, path, is_dir);
}

static int fs_readdir(int fanotify_fd, const char *path)
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
		ret = fs_init_cache(fanotify_fd, childpath, link->type == LINK_DIR);
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
 * >0 allow acces but keep watching
 *  0 allow access and stop watching
 */
static int handle_access_event(int fanotify_fd,
			       const struct fanotify_event_metadata *event,
			       const char *relpath, struct stat *st)
{
	off_t offset;
	int ret;

	switch (st->st_mode & S_IFMT) {
		case S_IFDIR:
			/* Allow dir to be accessed if all cache entries are created */
			/* TODO: populate a single child entry on FAN_LOOKUP_PERM event */
			ret = fs_readdir(fanotify_fd, relpath);
			break;
		case S_IFREG:
			/* Allow file to be accessed if all the file data is downloaded
			 * or if any block was downloaded, so reading the file sequetially
			 * to a read buffer smaller than download block size will work.
			 * TODO: download requested if we can get it from FAN_ACCESS_PERM event */
			offset = lseek(event->fd, 0, SEEK_HOLE);
			if (offset < 0)
				ret = -errno;
			else
				ret = fs_read(relpath, event->fd, st->st_size, 1);
			break;
		default:
			ret = -EPERM;
	}

	/* Deny modify content and truncate if cache is not fully populated */
	if (ret > 0 && event->mask & FAN_MODIFY_PERM)
		ret = -EROFS;

	return ret;
}

static void handle_events(int fanotify_fd)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[200];
	ssize_t len;
	char abspath[PATH_MAX];
	const char *relpath;
	ssize_t path_len;
	char procfd_path[PATH_MAX];
	struct fanotify_response_error response;
	int ret;

	len = read(fanotify_fd, (void *) &buf, sizeof(buf));
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

		lprintf(debug, "Got event 0x%08x on '%s' (%s)\n",
			metadata->mask, abspath, relpath);

		struct stat st;
		if (fstat(metadata->fd, &st))
			exit_perror("fstat");

		ret = -EPERM;
		if (metadata->mask & FAN_PRE_ACCESS) {
			ret = handle_access_event(fanotify_fd, metadata, relpath, &st);
		}

		response.fd = metadata->fd;
		if (ret < 0) {
			response.response = FAN_DENY_ERROR;
			response.error = -ret;
		} else {
			response.response = FAN_ALLOW;
			response.error = 0;
		}
		write(fanotify_fd, &response, sizeof(struct fanotify_response));
		if (!ret) {
			fanotify_remove_data_watch(fanotify_fd, relpath,
						   st.st_mode & S_IFDIR);
		}
		close(metadata->fd);
		metadata = FAN_EVENT_NEXT(metadata, len);
	}
}

static int fanotify_bind_mounted;

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

	if (DATA_DIR_fd > 0)
		close(DATA_DIR_fd);

	if (fanotify_bind_mounted)
		fanotify_mount_cleanup();

	exit_error("Terminated by signal");
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

void fanotify_watch_data_dir(int fanotify_fd)
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
	fanotify_add_root_watch(fanotify_fd, DATA_DIR);

	if (CONFIG.mount_dir &&
	    mount(DATA_DIR, CONFIG.mount_dir, NULL, MS_MOVE, NULL)) {
		fanotify_mount_cleanup();
		exit_perror("move mount data dir");
	}
}

int fanotify_main()
{
	int fanotify_fd;

	fanotify_fd = fanotify_init(FAN_INIT_XATTR_FLAGS, O_RDWR | O_LARGEFILE);
	if (fanotify_fd < 0) {
		/* Persistent marks not supported - fallback to evictable marks */
		ignore_mark_flags = FAN_MARK_IGNORE_SURV | FAN_MARK_EVICTABLE;
		fanotify_fd = fanotify_init(FAN_CLASS_PRE_CONTENT,
					    O_RDWR | O_LARGEFILE);
	}
	if (fanotify_fd < 0)
		exit_perror("fanotify_init");

	/* Watch events on data or mount dir */
	fanotify_watch_data_dir(fanotify_fd);

	for (;;)
		handle_events(fanotify_fd);

	close(fanotify_fd);
	return 0;
}
