#ifndef FUSE_LOCAL_H
#define FUSE_LOCAL_H

/**
 * \file fuse_local.h
 * \brief FUSE related functions
 */

/* Initialise fuse */
int fuse_local_init(int argc, char **argv);

/* Initialise fanotify and run event loop */
int fanotify_main();

/* Evict a file cache */
int fanotify_evict(const char *path);

#endif
