#ifndef __NSS_PGSQL_H_INCLUDED__
#  define __NSS_PGSQL_H_INCLUDED__

#  ifdef HAVE_CONFIG_H
#    include "config.h"
#  endif

#  ifdef HAVE_UNISTD_H
#    include <unistd.h>
#  endif

#  ifdef HAVE_NSS_H
#    include <nss.h>
#  endif

#  include <pwd.h>
#  include <grp.h>
#  include <sys/types.h>

int readconfig(void);
void cleanup(void);
char *getcfg(const char *key);

int backend_isopen(void);
int backend_open(void);
void backend_close(void);
void backend_prepare(const char *what);

enum nss_status backend_getpwent(struct passwd *result,
											char *buffer,
											size_t buflen,
											int *errnop);
enum nss_status backend_getgrent(struct group *result,
											char *buffer,
											size_t buflen,
											int *errnop);
enum nss_status backend_getpwuid(uid_t uid,
											struct passwd *result,
											char *buffer,
											size_t buflen,
											int *errnop);
enum nss_status backend_getgrgid(gid_t gid,
											struct group *result,
											char *buffer,
											size_t buflen,
											int *errnop);
enum nss_status backend_getgrnam(const char *name,
											struct group *result,
											char *buffer,
											size_t buflen,
											int *errnop);
enum nss_status backend_getpwnam(const char *name,
											struct passwd *result,
											char *buffer,
											size_t buflen,
											int *errnop);
size_t backend_initgroups_dyn(const char *user,
										gid_t group,
										long int *start,
										long int *size,
										gid_t **groupsp,
										long int limit,
										int *errnop);

void groupcpy(struct group *dest, struct group *src);
void passwdcpy(struct passwd *dest, struct passwd *src);
void print_err(const char *msg, ...);
void print_msg(const char *msg, ...);
size_t sql_escape(const char *from, char *to, size_t len);

#  ifdef DEBUG
#    define D(x) print_msg(x)
#  else
#    define D(x)
#  endif

#endif
