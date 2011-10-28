
AC_DEFUN(RSSH_CHECK_PROTOBUF,[
AC_REQUIRE([AC_PROG_CC])dnl
AC_ARG_WITH(protobuf, protobuf: prefix to installed protobuf-c library, PROTOBUF_PREFIX=${with_protobuf}, PROTOBUG_PREFIX="")

if test "x$PROTOBUF_PREFIX" = "x"
then
 if test -f /usr/include/google/protobuf-c/protobuf-c.h
 then
   PROTOBUF_INCLUDE_DIR=/usr/include
   PROTOBUF_PREFIX=/usr
 elif test -f /usr/local/include/google/protobuf-c/protobuf-c.h
 then
   PROTOBUF_PREFIX=/usr/local
   PROTOBUF_INCLUDE_DIR=/usr/local/include
 else
   PROTOBUF_INCLUDE_DIR=no
 fi
else
 PROTOBUF_INCLUDE_DIR=$PROTOBUF_PREFIX/include
fi

svCPPFLAGS=$CPPFLAGS
CPPFLAGS="$CPPFLAGS -I$PROTOBUF_INCLUDE_DIR"

AC_CHECK_HEADER(google/protobuf-c/protobuf-c.h, found=yes, found=no)
if test "x$found" = "xno" 
then
 AC_MSG_ERROR("protobuf-c headers not found");
fi

LIBS="$LIBS -lprotobuf-c"
AC_CHECK_LIB(protobuf-c, protobuf_c_message_get_packed_size, found=yes, found=no)
if test "x$found" = "xno" 
then
 AC_MSG_ERROR("protobuf-c library not found");
fi

 
])dnl
dnl
