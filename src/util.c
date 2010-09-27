/**
 * $Id: util.c,v 1.3 2001/10/01 05:50:16 mogul Exp $
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
#include <string.h>
#include <stdarg.h>


void print_err(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);

	fflush(stderr);
	exit(1);
}

void print_msg(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);

	fflush(stderr);
}

size_t sql_escape(const char *from, char *to, size_t len)
{
    const char *source = from;
    char *target = to;
    unsigned int remaining = len;

    while (remaining > 0) {
		  switch (*source) {
		  case '\0':
				*target = '\\';
				target++;
				*target = '0';
				break;

		  case '\\':
				*target = '\\';
				target++;
				*target = '\\';
				break;

		  case '\'':
				*target = '\\';
				target++;
				*target = '\'';
				break;

		  case '"':
				*target = '\\';
				target++;
				*target = '"';
				break;

		  default:
				*target = *source;
		  }
		  source++;
		  target++;
		  remaining--;
    }

    *target = '\0';

    return target - to;
}
