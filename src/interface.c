/**
 * $Id: interface.c,v 1.4 2001/10/05 10:44:39 mogul Exp $
 *
 * public interface to libc
 *
 * Copyright (c) 2001 by Joerg Wendland, Bret Mogilefsky
 * see included file COPYING for details
 *
 */

#include "nss-pgsql.h"
#include <stdio.h>
#include <stdlib.h>
#define _LIBC
#define NOT_IN_libc
#include <bits/libc-lock.h>

static __libc_lock_t  lock;

/*
 * passwd functions
 */
enum nss_status
_nss_pgsql_setpwent(void)
{
	 enum nss_status retval = NSS_STATUS_UNAVAIL;

	 __libc_lock_lock(lock);
  	 if(!backend_isopen()) {
		 backend_open();
  	 }
	 if(backend_isopen()) {
		 retval = backend_prepare_passwd();
	 }
	 __libc_lock_unlock(lock);

	 return retval;
}

enum nss_status
_nss_pgsql_endpwent(void)
{
	 __libc_lock_lock(lock);
	 backend_close();
	 __libc_lock_unlock(lock);

	 return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_pgsql_getpwent_r(struct passwd *result,
							 char *buffer,
							 size_t buflen,
							 int *errnop)
{
	 enum nss_status retval = NSS_STATUS_UNAVAIL;

	 __libc_lock_lock(lock);

	 // Make sure the database is opened in case no one has called setpwent()
	 if(!backend_isopen())
		 retval = _nss_pgsql_setpwent();

	 if(backend_isopen())
		 retval = backend_getpwent(result, buffer, buflen, errnop);

	 __libc_lock_unlock(lock);

	 return retval;
}

enum nss_status
_nss_pgsql_getpwnam_r(const char *pwnam,
							 struct passwd *result,
							 char *buffer,
							 size_t buflen,
							 int *errnop)
{
	 enum nss_status retval = NSS_STATUS_UNAVAIL;

	 __libc_lock_lock(lock);
	 if(backend_open()) {
		 retval = backend_getpwnam(pwnam, result, buffer, buflen, errnop);
		 backend_close();
	 }
	 __libc_lock_unlock(lock);

	 return retval;
}

enum nss_status
_nss_pgsql_getpwuid_r(uid_t uid,
							 struct passwd *result,
							 char *buffer,
							 size_t buflen,
							 int *errnop)
{
	enum nss_status retval = NSS_STATUS_UNAVAIL;

	 __libc_lock_lock(lock);
	 if(backend_open()) {
		 retval = backend_getpwuid(uid, result, buffer, buflen, errnop);
		 backend_close();
	 }
	 __libc_lock_unlock(lock);

	 return retval;
}

/*
 * group functions
 */
enum nss_status
_nss_pgsql_setgrent(void)
{
	enum nss_status retval = NSS_STATUS_UNAVAIL;

	 __libc_lock_lock(lock);
  	 if(!backend_isopen()) {
		 backend_open();
  	 }
	 if(backend_isopen()) {
		 retval = backend_prepare_group();
		 retval = NSS_STATUS_SUCCESS;
	 }
	 __libc_lock_unlock(lock);

	 return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_pgsql_endgrent(void)
{
	 __libc_lock_lock(lock);
	 backend_close();
	 __libc_lock_unlock(lock);

	 return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_pgsql_getgrent_r(struct group *result,
							 char *buffer,
							 size_t buflen,
							 int *errnop)
{
	enum nss_status retval = NSS_STATUS_UNAVAIL;

	 __libc_lock_lock(lock);

	 // Make sure the database is opened in case no one has called setpwent()
	 if(!backend_isopen())
		 retval = _nss_pgsql_setgrent();

	 if(backend_isopen())
		 retval = backend_getgrent(result, buffer, buflen, errnop);

	 __libc_lock_unlock(lock);

	 return retval;
}

enum nss_status
_nss_pgsql_getgrnam_r(const char *grnam,
							 struct group *result,
							 char *buffer,
							 size_t buflen,
							 int *errnop)
{
	enum nss_status retval = NSS_STATUS_UNAVAIL;

	 __libc_lock_lock(lock);
	 if(backend_open()) {
		 retval = backend_getgrnam(grnam, result, buffer, buflen, errnop);
		 backend_close();
	 }
	 __libc_lock_unlock(lock);

	 return retval;
}

enum nss_status
_nss_pgsql_getgrgid_r(uid_t gid,
							 struct group *result,
							 char *buffer,
							 size_t buflen,
							 int *errnop)
{
	enum nss_status retval = NSS_STATUS_UNAVAIL;

	__libc_lock_lock(lock);
	if(backend_open()) {
		retval = backend_getgrgid(gid, result, buffer, buflen, errnop);
		backend_close();
	}
	 __libc_lock_unlock(lock);

	 return retval;
}

enum nss_status
_nss_pgsql_initgroups_dyn(const char *user,
								  gid_t group,
								  long int *start,
								  long int *size,
								  gid_t **groupsp,
								  long int limit,
								  int *errnop)
{
	enum nss_status retval = NSS_STATUS_UNAVAIL;
	size_t numgroups;

	 __libc_lock_lock(lock);
	 if(backend_open()) {
		 numgroups = backend_initgroups_dyn(user, group, start, size, groupsp,
														limit, errnop);
		 retval = (numgroups > 0) ? NSS_STATUS_SUCCESS : NSS_STATUS_NOTFOUND;
		 backend_close();
	 }
	 __libc_lock_unlock(lock);

	 return retval;
}

