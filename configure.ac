AC_PREREQ([2.68])
AC_INIT([undup],
        [0.2],
        [https://github.com/radii/undup])

AC_CONFIG_SRCDIR([undup.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 foreign dist-bzip2])

AC_PROG_CC

AC_CHECK_LIB([crypto], [SHA256_Init])

AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset strerror strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
