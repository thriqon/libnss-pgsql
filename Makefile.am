SUBDIRS = src
EXTRA_DIST = acconfig.h doc/Makefile doc/nss-pgsql.sgml doc/nss-pgsql.txt doc/nss-pgsql.ps conf/nsswitch.conf conf/nss-pgsql.conf conf/dbschema.sql

doc/nss-pgsql.txt:doc/nss-pgsql.sgml
	make -C doc text

doc/nss-pgsql.ps:doc/nss-pgsql.sgml
	make -C doc postscript
