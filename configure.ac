AC_INIT([ima-inspect],
	[0.15],
	[https://github.com/mgerstner/ima-inspect/issues],
	[],
	[https://github.com/mgerstner/ima-inspect])

AC_PROG_CXX
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_FILES([Makefile])

PKG_CHECK_MODULES([TCLAP], [tclap])
AC_SEARCH_LIBS([imaevm_do_hexdump], [imaevm], [], [
	AC_MSG_ERROR([unable to find libimaevm, you need ima-evm-utils-devel (version 1.2 or newer) or similar package])
])

AC_OUTPUT
