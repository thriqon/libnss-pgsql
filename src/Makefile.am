lib_LTLIBRARIES = libnss_pgsql.la
libnss_pgsql_la_SOURCES = interface.c config.c backend.c util.c
libnss_pgsql_la_LDFLAGS = -module -version-info 2 -Wl,--version-script=$(srcdir)/libnss_pgsql.map
EXTRA_DIST = nss-pgsql.h libnss_pqsql.map

