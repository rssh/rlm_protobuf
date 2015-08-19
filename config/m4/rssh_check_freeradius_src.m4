
AC_DEFUN(RSSH_CHECK_FREERADIUS_SRC,[
AC_REQUIRE([AC_PROG_CC])dnl
AC_ARG_WITH(freeradius-src, freeradius-src: where configured copy of freeradius is exists, FREERADIUS_PREFIX=${with_freeradius_src}, FREERADIUS_PREFIX=no)

FREERADIUS_INCLUDE_DIR=$FREERADIUS_PREFIX/src

svCPPFLAGS=$CPPFLAGS
CPPFLAGS1="$svCPPFLAGS -I$FREERADIUS_INCLUDE_DIR"
CPPFLAGS2="$CPPFLAGS1 -I$FREERADIUS_INCLUDE_DIR -D RCSIDH(x,y)= "
CPPFLAGS=$CPPFLAGS2

AC_CHECK_HEADER(freeradius-devel/radius.h, fh=yes, fh=no)
AC_CHECK_HEADER(freeradius-devel/radiusd.h, fh=yes, fh=no)
if test "x$fh" = "xno" 
then
 AC_MSG_ERROR("freeradius headers not found");
fi

CPPFLAGS=$CPPFLAGS1
 
])dnl
dnl
