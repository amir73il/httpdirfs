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

#endif
