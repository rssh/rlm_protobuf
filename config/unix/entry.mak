#
# (C) Grad-Soft Ltd, 2011
# http://www.gradsoft.com.ua
#

PROJECT_ROOT=/home/rssh/work/rlm_protobuf
VERSION=0.5.0

#
CC=gcc
EXTRA_INCLUDES=-I$(COLLECTOR_DIR)
CPPFLAGS= -I/home/rssh/packages/freeradius/repo-rssh//src -I/usr/include -DHAVE_CONFIG_H -I. $(EXTRA_INCLUDES)
CFLAGS= -g -O2
LIBS=-lcurl    -lprotobuf-c
LD=ld
LDFLAGS=
LN_S=ln -s

#
INSTALL=/usr/bin/install -c
INSTALL_DATA=${INSTALL} -m 644
INSTALL_PROGRAM=${INSTALL}

prefix=/usr/local
install_bin_dir=/usr/local/bin
install_lib_dir=/usr/local/lib
install_idl_dir=/usr/local/idl
install_include_dir=/usr/local/include

