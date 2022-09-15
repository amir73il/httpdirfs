#include "link.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/fanotify.h>

#define FAN_EVENTS FAN_ACCESS_PERM

static void fanotify_add_watch(int fanotify_fd, const char *fn)
{
	char *path = Data_abspath(fn);

	if (fanotify_mark(fanotify_fd, FAN_MARK_ADD, FAN_EVENTS | FAN_ONDIR,
			  AT_FDCWD, path)) {
		exit_perror("fanotify_mark");
	}

	printf("Added fanotify access watch on path %s\n", path);
	FREE(path);
}

static void fanotify_remove_watch(int fanotify_fd, const char *path)
{
	if (fanotify_mark(fanotify_fd, FAN_MARK_REMOVE, FAN_EVENTS | FAN_ONDIR,
			  AT_FDCWD, path)) {
		exit_perror("fanotify_mark");
	}

	printf("Removed fanotify access watch on path %s\n", path);
}

static int fs_readdir(int fanotify_fd, const char *abspath)
{
	const char *path = Data_relpath(abspath);
	size_t pathlen;
	char childpath[PATH_MAX];
	LinkTable *linktbl;

	if (!path)
		return -EINVAL;

	if (!*path || !strcmp(path, "/")) {
		linktbl = ROOT_LINK_TBL;
	} else {
		linktbl = path_to_Link_LinkTable_new(path);
		if (!linktbl) {
			return -ENOENT;
		}
	}

	pathlen = strlen(path);
	strcpy(childpath, path);
	childpath[pathlen++] = '/';

	/* We skip the head link */
	for (int i = 1; i < linktbl->num; i++) {
		Link *link = linktbl->links[i];
		switch (link->type) {
			case LINK_DIR:
				sprintf(childpath + pathlen, "%s/", link->linkname);
				CacheDir_create(childpath);
				break;
			case LINK_FILE:
				sprintf(childpath + pathlen, "%s", link->linkname);
				Cache_create(childpath);
				break;
			default:
				continue;
		}
		fanotify_add_watch(fanotify_fd, childpath);
	}

	return 0;
}

static int fs_read(const char *abspath, off_t offset, size_t size)
{
	const char *path = Data_relpath(abspath);
	Link *link = path_to_Link(path);
	if (!link)
		return -ENOENT;

	Cache *cache = Cache_open(path);
	if (!cache)
		return -ENOENT;

	/* Read via cache into "/dev/null" to populate cache */
	long recv = Cache_read(cache, NULL, size, offset);

	Cache_close(cache);

	return recv != (long)size;
}


static void handle_events(int fanotify_fd)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[200];
	ssize_t len;
	char abspath[PATH_MAX];
	ssize_t path_len;
	char procfd_path[PATH_MAX];
	struct fanotify_response response;
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

		lprintf(debug, "Got event 0x%08x on '%s'\n",
			metadata->mask, abspath);

		struct stat st;
		if (fstat(metadata->fd, &st))
			exit_perror("fstat");

		switch (st.st_mode & S_IFMT) {
			case S_IFDIR:
				/* Allow dir to be accessed if all cache entries are created */
				/* TODO: populate a single child entry on FAN_LOOKUP_PERM event */
				ret = fs_readdir(fanotify_fd, abspath);
				break;
			case S_IFREG:
				/* Allow file to be accessed if all the file data is downloaded */
				/* TODO: download range if we can get it from FAN_ACCESS_PERM event */
				ret = fs_read(abspath, 0, st.st_size);
				break;
			default:
				ret = -EPERM;
		}

		response.fd = metadata->fd;
		response.response = ret ? FAN_DENY : FAN_ALLOW;
		write(fanotify_fd, &response, sizeof(struct fanotify_response));
		if (!ret)
			fanotify_remove_watch(fanotify_fd, abspath);

		close(metadata->fd);
		metadata = FAN_EVENT_NEXT(metadata, len);
	}
}

int fanotify_main()
{
	int fanotify_fd;

	fanotify_fd = fanotify_init(FAN_CLASS_PRE_CONTENT, O_RDONLY | O_LARGEFILE);
	if (fanotify_fd < 0)
		exit_perror("fanotify_init");

	/* Hook on first access to data root dir */
	fanotify_add_watch(fanotify_fd, "");

	for (;;)
		handle_events(fanotify_fd);

	close(fanotify_fd);
	return 0;
}
