lib_LTLIBRARIES = libnss_pgsql.la
libnss_pgsql_la_SOURCES = interface.c config.c backend.c util.c
libnss_pgsql_la_LDFLAGS = -module -version-info 2
EXTRA_DIST = nss-pgsql.h

libnss_pgsql_ls_CPPFALGS = -DLIBDIR=\"$(libdir)\" -DSYSCONFDIR=\"$(sysconfdir)\" -D_GNU_SOURCE
