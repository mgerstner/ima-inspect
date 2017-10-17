AC_INIT([ima-inspect],
	[0.1],
	[https://github.com/mgerstner/ima-inspect/issues],
	[],
	[https://github.com/mgerstner/ima-inspect])

AC_PROG_CXX
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_FILES([Makefile])

PKG_CHECK_MODULES([TCLAP], [tclap])
AC_CHECK_LIB([imaevm], [do_dump])

AC_OUTPUT
