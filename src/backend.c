/**
 * $Id: backend.c,v 1.5 2001/10/05 10:44:39 mogul Exp $
 *
 * database backend functions
 *
 * Copyright (c) 2001 by Joerg Wendland, Bret Mogilefsky
 * see included file COPYING for details
 *
 */

#include "nss-pgsql.h"
#include <postgresql/libpq-fe.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

static PGconn *_conn = NULL;
static int _isopen = 0;

int backend_isopen()
{
	return (_isopen > 0);
}

/*
 * read configuration and connect to database
 */
int backend_open()
{
	if(!_isopen) {
		if(readconfig()) {
			_conn = PQsetdbLogin(getcfg("host"),
										getcfg("port"),
										"", "",
										getcfg("database"),
										getcfg("login"),
										getcfg("passwd"));
			if(PQstatus(_conn) == CONNECTION_OK) {
				PQexec(_conn, "BEGIN TRANSACTION");
				_isopen++;
			} else {
				print_msg("\nCould not connect to database\n");
			}
		}
	}

	return (_isopen > 0);
}

/*
 * close connection to database and clean up configuration
 */
void backend_close()
{
	 _isopen--;
	 if(!_isopen) {
		  PQexec(_conn, "COMMIT");
		  PQfinish(_conn);
		  _conn = NULL;
	 }
	 if(_isopen < 0)
		  _isopen = 0;
}

/*
 *  prepare a cursor in database
 */
inline void backend_prepare(const char *what)
{
	 char *stmt, *cfgname;
	 asprintf(&cfgname, "%stable", what);
	 asprintf(&stmt, "DECLARE nss_pgsql_internal_%s_curs CURSOR FOR "
				 "SELECT * FROM %s FOR READ ONLY", what, getcfg(cfgname));
	 PQexec(_conn, stmt);
	 free(cfgname);
	 free(stmt);
}


/*
  With apologies to nss_ldap...
  Assign a single value to *valptr from the specified row in the result
*/
enum nss_status
copy_attrval_n(PGresult *res,
				  const char *attr,
				  char **valptr, char **buffer, size_t *buflen, int row)
{

	const char *sptr;
	size_t slen;

	sptr = PQgetvalue(res, row, PQfnumber(res, getcfg(attr)));
	slen = strlen(sptr);
	if(*buflen < slen+1) {
		return NSS_STATUS_TRYAGAIN;
	}
	strncpy(*buffer, sptr, slen);
	(*buffer)[slen] = '\0';
		
	*valptr = *buffer;

	*buffer += slen + 1;
	*buflen -= slen + 1;

	return NSS_STATUS_SUCCESS;
}


/*
  With apologies to nss_ldap...
  Assign a single value to *valptr.
*/
enum nss_status
copy_attrval (PGresult *res,
				  const char *attr,
				  char **valptr, char **buffer, size_t *buflen)
{
	return copy_attrval_n(res, attr, valptr, buffer, buflen, 0);
}


/*
 * return array of strings containing usernames that are member of group with gid 'gid'
 */
enum nss_status getgroupmem(gid_t gid,
									 struct group *result,
									 char *buffer,
									 size_t buflen)
{
	char *stmt;
	PGresult *res;
	int n, t = 0;
	enum nss_status status = NSS_STATUS_NOTFOUND;
	size_t ptrsize;

	asprintf(&stmt, "SELECT %s FROM %s WHERE %s.%s = %d", 
				getcfg("group_member"), 
				getcfg("groupmembertable"),
				getcfg("grouptable"),
				getcfg("group_gid"),
				gid);
	res = PQexec(_conn, stmt);

	if(!PQresultStatus(res)!=PGRES_TUPLES_OK)
		goto BAIL_OUT;

	n = PQntuples(res);

	// Make sure there's enough room for the array of pointers to group member names
	ptrsize = (n+1) * sizeof(const char *);
	if(buflen < ptrsize) {
		status = NSS_STATUS_TRYAGAIN;
		goto BAIL_OUT;
	}

	result->gr_mem = (char**)buffer;

	buffer += ptrsize;
	buflen -= ptrsize;

	status = NSS_STATUS_SUCCESS;

	for(t = 0; t < n; t++) {
		status = copy_attrval_n(res, "group_member", &(result->gr_mem[t]), &buffer, &buflen, t);
		if(status != NSS_STATUS_SUCCESS)
			goto BAIL_OUT;
	}
	result->gr_mem[n] = NULL;
	
 BAIL_OUT:

	PQclear(res);
	free(stmt);

	return status;
}

/*
 * 'convert' a PGresult to struct group
 */
enum nss_status res2grp(PGresult *res,
								struct group *result,
								char *buffer,
								size_t buflen)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;

#ifdef COMMENTED_OUT
	char **i;
#endif	

	if(!PQntuples(res))
		goto BAIL_OUT;

	// Carefully copy attributes into buffer.  Return NSS_STATUS_TRYAGAIN if not enough room.
	status = copy_attrval (res, "group_name"  , &result->gr_name    , &buffer, &buflen);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attrval (res, "group_passwd", &result->gr_passwd  , &buffer, &buflen);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	result->gr_gid = (gid_t) atol(PQgetvalue(res, 0, PQfnumber(res, getcfg("group_gid"))));

	status = getgroupmem(result->gr_gid, result, buffer, buflen);
 
#ifdef COMMENTED_OUT
	print_msg("Converted a res to a grp:\n");
	print_msg("GID: %d\n", result->gr_gid);
	print_msg("Name: %s\n", result->gr_name);
	print_msg("Password: %s\n", result->gr_passwd);
	i = result->gr_mem;
	while(*i)
		print_msg("Member: %s\n", *i++);
	print_msg("\n");
#endif

 BAIL_OUT:
	return status;
}

/*
 * 'convert' a PGresult to struct passwd
 */
enum nss_status res2pwd(PGresult *res, struct passwd *result,
								char *buffer,
								size_t buflen)
{
	enum nss_status status = NSS_STATUS_NOTFOUND;

	if(!PQntuples(res))
		goto BAIL_OUT;

	// Carefully copy attributes into buffer.  Return NSS_STATUS_TRYAGAIN if not enough room.
	status = copy_attrval (res, "passwd_name"  , &result->pw_name  , &buffer, &buflen);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attrval (res, "passwd_passwd", &result->pw_passwd, &buffer, &buflen);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attrval (res, "passwd_gecos" , &result->pw_gecos , &buffer, &buflen);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attrval (res, "passwd_dir"   , &result->pw_dir   , &buffer, &buflen);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attrval (res, "passwd_shell" , &result->pw_shell , &buffer, &buflen);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	// Can be less careful with uid/gid
	result->pw_uid = (uid_t) atol(PQgetvalue(res, 0, PQfnumber(res, getcfg("passwd_uid"))));
	result->pw_gid = (gid_t) atol(PQgetvalue(res, 0, PQfnumber(res, getcfg("passwd_gid"))));

#ifdef COMMENTED_OUT
	print_msg("Converted a res to a pwd:\n");
	print_msg("UID: %d\n", result->pw_uid);
	print_msg("GID: %d\n", result->pw_gid);
	print_msg("Name: %s\n", result->pw_name);
	print_msg("Password: %s\n", result->pw_passwd);
	print_msg("Gecos: %s\n", result->pw_gecos);
	print_msg("Dir: %s\n", result->pw_dir);
	print_msg("Shell: %s\n", result->pw_shell);
#endif

 BAIL_OUT:
	return status;
}

/*
 * fetch a row from cursor
 */
PGresult *fetch(char *what)
{
	 char *stmt;
	 PGresult *res;

	 asprintf(&stmt, "FETCH FROM nss_pgsql_internal_%s_curs", what);
	 if(_conn == NULL) {
		 D("Did a fetch with the database closed!");
	 }
	 if(PQstatus(_conn) != CONNECTION_OK) {
		  D("oops! die connection is futsch");
		  return NULL;
	 }
	 res = PQexec(_conn, stmt);
	 free(stmt);

	 return res;
}

/*
 * get a group entry from cursor
 */
enum nss_status backend_getgrent(struct group *result,
											char *buffer,
											size_t buflen,
											int *errnop)
{
	PGresult *res;
	enum nss_status status = NSS_STATUS_NOTFOUND;

	res = fetch("group");
	if(res) {
		status = res2grp(res, result, buffer, buflen);
		PQclear(res);
	}
	return status;
}    

/*
 * get a passwd entry from cursor
 */
enum nss_status backend_getpwent(struct passwd *result,
											char *buffer,
											size_t buflen,
											int *errnop)
{
	PGresult *res;
	enum nss_status status = NSS_STATUS_NOTFOUND;

	res = fetch("passwd");
	if(res) {
		status = res2pwd(res, result, buffer, buflen);
		PQclear(res);
	}
	return status;
}    

/*
 * backend for getpwnam()
 */
enum nss_status backend_getpwnam(const char *name,
											struct passwd *result,
											char *buffer,
											size_t buflen,
											int *errnop)
{
	 char *stmt, *ename;
	 PGresult *res;
	 size_t len;
	 enum nss_status status = NSS_STATUS_NOTFOUND;

	 len = strlen(name);
	 ename = malloc(2*len+1);
	 sql_escape(name, ename, len);
	 asprintf(&stmt, "SELECT * FROM %s WHERE %s = '%s'",
				 getcfg("passwdtable"),
				 getcfg("passwd_name"),
				 ename);

	 res = PQexec(_conn, stmt);
	 if(res) {
		 status = res2pwd(res, result, buffer, buflen);
		 PQclear(res);
	 }
	 free(stmt);
	 free(ename);
    
	 return status;
}

/*
 * backend for getpwuid()
 */
enum nss_status backend_getpwuid(uid_t uid,
											struct passwd *result,
											char *buffer,
											size_t buflen,
											int *errnop)
{
	 char *stmt;
	 PGresult *res;
	 enum nss_status status = NSS_STATUS_NOTFOUND;
    
	 asprintf(&stmt, "SELECT * FROM %s WHERE %s = %d",
				 getcfg("passwdtable"),
				 getcfg("passwd_uid"),
				 uid);
	 res = PQexec(_conn, stmt);
	 if(res) {
		 status = res2pwd(res, result, buffer, buflen);
		 PQclear(res);
	 }
	 free(stmt);
    
	 return status;
}

/*
 * backend for getgrnam()
 */
enum nss_status backend_getgrnam(const char *name,
											struct group *result,
											char *buffer,
											size_t buflen,
											int *errnop)
{
	 char *stmt, *ename;
	 PGresult *res;
	 size_t len;
	 enum nss_status status = NSS_STATUS_NOTFOUND;
    
	 len = strlen(name);
	 ename = malloc(2*len+1);
	 sql_escape(name, ename, len);

	 asprintf(&stmt, "SELECT * FROM %s WHERE %s = '%s'",
				 getcfg("grouptable"),
				 getcfg("group_name"),
				 ename);
	 res = PQexec(_conn, stmt);
	 if(res) {
		 status = res2grp(res, result, buffer, buflen);
		 PQclear(res);
	 }

	 free(stmt);
	 free(ename);
    
	 return status;
}


/*
 * backend for getgrgid()
 */
enum nss_status backend_getgrgid(gid_t gid,
											struct group *result,
											char *buffer,
											size_t buflen,
											int *errnop)
{
	 char *stmt;
	 PGresult *res;
	 enum nss_status status = NSS_STATUS_NOTFOUND;
    
	 asprintf(&stmt, "SELECT * FROM %s WHERE %s = %d",
				 getcfg("grouptable"),
				 getcfg("group_gid"),
				 gid);
	 res = PQexec(_conn, stmt);
	 if(res) {
		 status = res2grp(res, result, buffer, buflen);
		 PQclear(res);
	 }
	 free(stmt);
    
	 return status;
}


size_t backend_initgroups_dyn(const char *user,
										gid_t group,
										long int *start,
										long int *size,
										gid_t **groupsp,
										long int limit,
										int *errnop)
{
	 char *stmt, *euser;
	 PGresult *res;
	 size_t len;
	 gid_t *groups = *groupsp;
	 int rows;

	 len = strlen(user);
	 euser = malloc(2*len+1);
	 sql_escape(user, euser, len);

	 asprintf(&stmt, "SELECT %s.%s FROM %s WHERE %s = '%s' AND %s.%s != %d",
				 getcfg("grouptable"),
				 getcfg("group_gid"),
				 getcfg("groupmembertable"),
				 getcfg("group_member"),
				 euser,
				 getcfg("grouptable"),
				 getcfg("group_gid"),
				 group);
	 res = PQexec(_conn, stmt);

	 rows = PQntuples(res);

	 if(rows+(*start) > *size) {
		  // Have to make the result buffer bigger
		  long int newsize = rows + (*start);
		  newsize = (limit > 0) ? MIN(limit, newsize) : newsize;
		  *groupsp = groups = realloc(groups, newsize * sizeof(*groups));
		  *size = newsize;
	 }
	
	 rows = (limit > 0) ? MIN(rows, limit - *start) : rows;

	 while(rows--) {
		  groups[*start] = atoi(PQgetvalue(res, rows,
													  PQfnumber(res, getcfg("group_gid"))));
		  *start += 1;
	 }
	
	 PQclear(res);
	 free(stmt);
	 free(euser);
    
	 return *start;
}
