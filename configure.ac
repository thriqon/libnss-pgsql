AC_PREREQ(2.59)
AC_INIT([nsspampgsql],[1.1],[libnsspgsql1@packages.debian.org])
AC_CONFIG_AUX_DIR([autoconf])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([AUTHORS])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_CPP
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([pq], [PQsetdbLogin])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h unistd.h nss.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit strstr])

AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])
AC_OUTPUT
