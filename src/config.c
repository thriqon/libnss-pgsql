/**
 * $Id: config.c,v 1.5 2001/10/05 10:44:39 mogul Exp $
 *
 * configfile parser
 *
 * Copyright (c) 2001 by Joerg Wendland, Bret Mogilefsky
 * see included file COPYING for details
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "nss-pgsql.h"

#define HASHMAX 73
#define CFGLINEMAX 256
#define CFGFILE SYSCONFDIR"/nss-pgsql.conf"

static char *_options[HASHMAX];
static unsigned int _isopen = 0;

unsigned int texthash(const char *str);


/*
 * create a simple hash from a string
 */
unsigned int texthash(const char *str)
{
	 int i, s;

	 for(i = s = 0; str[i]; i++)
		  s += str[i];

	 return s % HASHMAX;
}

/*
 * read configfile and save values in hashtable
 */
int readconfig(void)
{
	FILE *cf;
	char line[CFGLINEMAX], key[CFGLINEMAX], val[CFGLINEMAX], *c;
	unsigned int h;
	unsigned int lineno = 0;

	if(_isopen)
		return 1;
	
	if(!(cf = fopen(CFGFILE, "r"))) {
		print_msg("could not open config file " CFGFILE "\n");
		return 0;
	}

	while(fgets(line, CFGLINEMAX, cf)) {
		lineno++;

		/* remove comments */
		c = strstr(line, "#");
		if(c) {
			line[c-line] = 0;
		}

		if (*line == 0 || *line == '\n')
			continue;

		/* read options */
		if(sscanf(line, " %s = %[^\n]", key, val) < 2) {
			print_err("line %d in " CFGFILE " is unparseable: \"%s\"\n", lineno, line);
		} else {
			h = texthash(key);
			_options[h] = malloc(strlen(val)+1);
			strcpy(_options[h], val);
		}
	}
	fclose(cf);

	_isopen = 1;
	atexit(cleanup);

	return 1;
}

/*
 * free the hashmap, close connection to db if open
 */
void cleanup(void)
{
	 int i;

	 if(_isopen)
		 for(i = 0; i < HASHMAX; i++)
			 free(_options[i]);
	 _isopen = 0;

	 while(backend_isopen())
		 backend_close();
}


/*
 * get value for 'key' from the hashmap
 */
inline char *getcfg(const char *key)
{
	 return _options[texthash(key)];
}
