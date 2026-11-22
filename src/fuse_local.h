#ifndef FUSE_LOCAL_H
#define FUSE_LOCAL_H

/**
 * \file fuse_local.h
 * \brief FUSE related functions
 */

/* Initialise fuse */
int fuse_local_init(int argc, char **argv);

/* Expose the cache data dir at mountpoint and populate it with fanotify */
int fanotify_main(const char *mountpoint);

#endif
