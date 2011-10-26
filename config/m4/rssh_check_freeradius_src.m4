
AC_DEFUN(RSSH_CHECK_FREERADIUS_SRC,[
AC_REQUIRE([AC_PROG_CC])dnl
AC_ARG_WITH(freeradius-src, freeradius-src: where configured copy of freeradius is exists, FREERADIUS_PREFIX=${with_freeradius_src}, FREERADIUS_PREFIX=no)

FREERADIUS_INCLUDE_DIR=$FREERADIUS_PREFIX/src

svCPPFLAGS=$CPPFLAGS
CPPFLAGS="$CPPFLAGS -I$FREERADIUS_INCLUDE_DIR"

AC_CHECK_HEADER(freeradius-devel/radius.h, fh=yes, fh=no)
AC_CHECK_HEADER(freeradius-devel/radiusd.h, fh=yes, fh=no)
if test "x$fh" = "xno" 
then
 AC_MSG_ERROR("freeradius headers not found");
fi
 
])dnl
dnl
