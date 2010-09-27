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

// column number in passwd file
#define PASSWD_NAME 0
#define PASSWD_PASSWD 1
#define PASSWD_UID 2
#define PASSWD_GID 3
#define PASSWD_GECOS 4
#define PASSWD_DIR 5
#define PASSWD_SHELL 6

// column number in group file 
#define GROUP_NAME 0
#define GROUP_PASSWD 1
#define GROUP_GID 2

// Not used
#define GROUP_MEMBER 4

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
			char* conninfo;
			asprintf(&conninfo,
				"host=%s port=%s dbname=%s user=%s password=%s",
				getcfg("host"),
				getcfg("port"),
				getcfg("database"),
				getcfg("login"),
				getcfg("passwd"));
			_conn = PQconnectdb(conninfo);
			free(conninfo);
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
 *  prepare a cursor in database for passwd
 */
inline enum nss_status backend_prepare_passwd()
{
	char *stmt, *cfgname;
	PGresult *res;
	ExecStatusType status;
/*
	print_msg("-------------\n");
	stmt = getcfg("querypasswd"); 
	if ( stmt != NULL ) print_msg("%s\n",stmt);
	stmt = getcfg("querygroup"); 
	if ( stmt != NULL ) print_msg("%s\n",stmt);
	stmt = getcfg("querygroupmember"); 
	if ( stmt != NULL ) print_msg("%s\n",stmt);
	print_msg("-------------\n");
*/
	if ((cfgname = getcfg("querypasswd")) != NULL) {
		asprintf(&stmt, "DECLARE nss_pgsql_internal_passwd_curs CURSOR FOR "
			"%s FOR READ ONLY",
			cfgname);
	} else {
		asprintf(&stmt, "DECLARE nss_pgsql_internal_passwd_curs CURSOR FOR "
	 		"SELECT %s,%s,%s,%s,%s,%s,%s FROM %s FOR READ ONLY",
			getcfg("passwd_name"),
			getcfg("passwd_passwd"),
			getcfg("passwd_uid"),
			getcfg("passwd_gid"),
			getcfg("passwd_gecos"),
			getcfg("passwd_dir"),
			getcfg("passwd_shell"),
			getcfg("passwdtable"));
	}
	//print_msg("%s backend_prepare_passwd\n",stmt); //CB
	res=PQexec(_conn, stmt);
	status=PQresultStatus(res);
	PQclear(res);
	free(stmt);

	if (status==PGRES_COMMAND_OK)
		return NSS_STATUS_SUCCESS;
	else
		return NSS_STATUS_UNAVAIL;
}

/*
 *  prepare a cursor in database for group
 */
inline enum nss_status backend_prepare_group()
{
	 char *stmt, *cfgname;
	PGresult *res;
	ExecStatusType status;

	if ( (cfgname=getcfg("querygroup")) != NULL) {
		asprintf(&stmt, "DECLARE nss_pgsql_internal_group_curs CURSOR FOR "
			"%s FOR READ ONLY",
			cfgname);
	} else {
	 	asprintf(&stmt, "DECLARE nss_pgsql_internal_group_curs CURSOR FOR "
	 		"SELECT %s,%s,%s FROM %s FOR READ ONLY",
			getcfg("group_name"),
			getcfg("group_passwd"),
			getcfg("group_gid"),
			getcfg("grouptable"));
	}
	//print_msg("%s backend_prepare_group\n",stmt); //CB
	res=PQexec(_conn, stmt);
	status=PQresultStatus(res);
	PQclear(res);
	 free(stmt);

	if (status==PGRES_COMMAND_OK)
		return NSS_STATUS_SUCCESS;
	else
		return NSS_STATUS_UNAVAIL;
}


/*
  With apologies to nss_ldap...
  Assign a single value to *valptr from the specified row in the result
*/
/* Unused CB
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
*/

/*
  With apologies to nss_ldap...
  Assign a single value to *valptr.
*/
/* Unused CB
enum nss_status
copy_attrval (PGresult *res,
				  const char *attr,
				  char **valptr, char **buffer, size_t *buflen)
{
	return copy_attrval_n(res, attr, valptr, buffer, buflen, 0);
}
*/

/*
  With apologies to nss_ldap...
  Assign a single value to *valptr from the specified row in the result
  Copy the sql attr in column colnum
*/
enum nss_status
copy_attr_colnum(PGresult *res,
				  int colnum,
				  char **valptr, char **buffer, size_t *buflen, int row)
{

	const char *sptr;
	size_t slen;

	sptr = PQgetvalue(res, row, colnum);
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
 * return array of strings containing usernames that are member of group with gid 'gid'
 */
enum nss_status getgroupmem(gid_t gid,
									 struct group *result,
									 char *buffer,
									 size_t buflen)
{
	char *stmt, *cfgname;
	PGresult *res;
	int n, t = 0;
	enum nss_status status = NSS_STATUS_NOTFOUND;
	size_t ptrsize;

	if ( (cfgname=getcfg("querymembers")) != NULL) {
		asprintf(&stmt, cfgname, gid);
	} else {
		asprintf(&stmt, "SELECT %s FROM %s WHERE %s.%s = %d", 
			getcfg("group_member"), 
			getcfg("groupmembertable"),
			getcfg("grouptable"),
			getcfg("group_gid"),
			gid);
	}
	//print_msg("getgroupmem stmt %s\n",stmt); //CB
	res = PQexec(_conn, stmt);

	if (PQresultStatus(res)!=PGRES_TUPLES_OK) {
		status=NSS_STATUS_UNAVAIL;
		goto BAIL_OUT;
	}

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
		//status = copy_attrval_n(res, "group_member", &(result->gr_mem[t]), &buffer, &buflen, t);
		status = copy_attr_colnum(res, 0, &(result->gr_mem[t]), &buffer, &buflen, t);
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
#ifdef DEBUG
	char **i;
#endif	

	if(!PQntuples(res))
		goto BAIL_OUT;

	// Carefully copy attributes into buffer.  Return NSS_STATUS_TRYAGAIN if not enough room.
	status = copy_attr_colnum (res, GROUP_NAME  , &result->gr_name    , &buffer, &buflen, 0);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attr_colnum (res, GROUP_PASSWD, &result->gr_passwd  , &buffer, &buflen, 0);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	result->gr_gid = (gid_t) atol(PQgetvalue(res, 0, GROUP_GID));

	status = getgroupmem(result->gr_gid, result, buffer, buflen);
 
#ifdef DEBUG
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
	status = copy_attr_colnum (res, PASSWD_NAME  , &result->pw_name  , &buffer, &buflen, 0);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attr_colnum (res, PASSWD_PASSWD, &result->pw_passwd, &buffer, &buflen, 0);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attr_colnum (res, PASSWD_GECOS , &result->pw_gecos , &buffer, &buflen, 0);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attr_colnum (res, PASSWD_DIR   , &result->pw_dir   , &buffer, &buflen, 0);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	status = copy_attr_colnum (res, PASSWD_SHELL , &result->pw_shell , &buffer, &buflen, 0);
	if(status != NSS_STATUS_SUCCESS) goto BAIL_OUT;

	// Can be less careful with uid/gid
	result->pw_uid = (uid_t) atol(PQgetvalue(res, 0, PASSWD_UID));
	result->pw_gid = (gid_t) atol(PQgetvalue(res, 0, PASSWD_GID));

#ifdef DEBUG
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
	if (PQresultStatus(res)==PGRES_TUPLES_OK)
		status = res2grp(res, result, buffer, buflen);
	else
		status = NSS_STATUS_UNAVAIL;

		PQclear(res);
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
	if (PQresultStatus(res)==PGRES_TUPLES_OK)
		status = res2pwd(res, result, buffer, buflen);
	else
		status = NSS_STATUS_UNAVAIL;

		PQclear(res);

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
	 char *stmt, *cfgname, *ename;
	 PGresult *res;
	 size_t len;
	 enum nss_status status = NSS_STATUS_NOTFOUND;

	 len = strlen(name);
	 ename = malloc(2*len+1);
	 sql_escape(name, ename, len);
	if ( (cfgname=getcfg("querypasswd")) != NULL) {
		asprintf(&stmt, "%s WHERE %s = '%s'",
			cfgname,
			getcfg("passwd_name"),
			ename );
	} else {
	 	asprintf(&stmt, "SELECT %s,%s,%s,%s,%s,%s,%s FROM %s WHERE %s = '%s'",
			getcfg("passwd_name"),
			getcfg("passwd_passwd"),
			getcfg("passwd_uid"),
			getcfg("passwd_gid"),
			getcfg("passwd_gecos"),
			getcfg("passwd_dir"),
			getcfg("passwd_shell"),
			getcfg("passwdtable"),
			getcfg("passwd_name"),
			ename);
	}
	//print_msg("%s backend_getpwnam\n",stmt); //CB

	 res = PQexec(_conn, stmt);
	if (PQresultStatus(res)==PGRES_TUPLES_OK) {
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
	 char *stmt, *cfgname;
	 PGresult *res;
	 enum nss_status status = NSS_STATUS_NOTFOUND;
    
	if ( (cfgname=getcfg("querypasswd")) != NULL) {
		asprintf(&stmt, "%s WHERE %s = %d",
			cfgname,
			getcfg("passwd_uid"),
			uid);
	} else {
	 	asprintf(&stmt, "SELECT %s,%s,%s,%s,%s,%s,%s FROM %s WHERE %s = %d",
			getcfg("passwd_name"),
			getcfg("passwd_passwd"),
			getcfg("passwd_uid"),
			getcfg("passwd_gid"),
			getcfg("passwd_gecos"),
			getcfg("passwd_dir"),
			getcfg("passwd_shell"),
			getcfg("passwdtable"),
			getcfg("passwd_uid"),
			uid);
	}
	//print_msg("backend_getpwuid :: %s\n",stmt); //CB
	 res = PQexec(_conn, stmt);
	 if (PQresultStatus(res)==PGRES_TUPLES_OK) {
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
	 char *stmt, *cfgname, *ename;
	 PGresult *res;
	 size_t len;
	 enum nss_status status = NSS_STATUS_NOTFOUND;
    
	 len = strlen(name);
	 ename = malloc(2*len+1);
	 sql_escape(name, ename, len);

	if ( (cfgname=getcfg("querygroup")) != NULL) {
		asprintf(&stmt, "%s WHERE %s = '%s'",
			cfgname,
			getcfg("group_name"),
			ename);
	} else {
	 	asprintf(&stmt, "SELECT %s,%s,%s FROM %s WHERE %s = '%s'",
			getcfg("group_name"),
			getcfg("group_passwd"),
			getcfg("group_gid"),
			getcfg("grouptable"),
			getcfg("group_name"),
			ename);
	}
	//print_msg("%s backend_getgrnam\n",stmt); //CB
	 res = PQexec(_conn, stmt);
	 if (PQresultStatus(res)!=PGRES_TUPLES_OK)
		 status = NSS_STATUS_UNAVAIL;
	 else if (PQntuples(res)>0)
		 status = res2grp(res, result, buffer, buflen);

		 PQclear(res);

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
	 char *stmt, *cfgname;
	 PGresult *res;
	 enum nss_status status = NSS_STATUS_NOTFOUND;
    
	if ( (cfgname=getcfg("querygroup")) != NULL) {
		asprintf(&stmt, "%s WHERE %s = %d",
			cfgname,
			getcfg("group_gid"),
			gid);
	} else {
	 	asprintf(&stmt, "SELECT %s,%s,%s FROM %s WHERE %s = %d",
			getcfg("group_name"),
			getcfg("group_passwd"),
			getcfg("group_gid"),
			getcfg("grouptable"),
			getcfg("group_gid"),
			gid);
	}
	//print_msg("%s backend_getgrgid\n",stmt); //CB
	 res = PQexec(_conn, stmt);
	 if(PQresultStatus(res)==PGRES_TUPLES_OK)
		 status = res2grp(res, result, buffer, buflen);
		 PQclear(res);
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
	 char *stmt, *cfgname, *euser;
	 PGresult *res;
	 size_t len;
	 gid_t *groups = *groupsp;
	 int rows;

	 len = strlen(user);
	 euser = malloc(2*len+1);
	 sql_escape(user, euser, len);

	 if ( (cfgname=getcfg("queryids")) != NULL) {
		asprintf(&stmt, cfgname, euser, group);
	 } else {
		asprintf(&stmt, "SELECT %s.%s FROM %s WHERE %s = '%s' AND %s.%s != %d",
			getcfg("grouptable"),
			getcfg("group_gid"),
			getcfg("groupmembertable"),
			getcfg("group_member"),
			euser,
			getcfg("grouptable"),
			getcfg("group_gid"),
			group);
	 }
	 //print_msg("%s backend_initgroups_dyn\n",stmt); //CB
	 res = PQexec(_conn, stmt);

	 if (PQresultStatus(res)!=PGRES_TUPLES_OK) {
			 PQclear(res);
			 return 0;
	 }


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
		  //groups[*start] = atoi(PQgetvalue(res, rows, PQfnumber(res, getcfg("group_gid"))));
		  groups[*start] = atoi(PQgetvalue(res, rows, 0));
		  *start += 1;
	 }
	
	 PQclear(res);
	 free(stmt);
	 free(euser);
    
	 return *start;
}
