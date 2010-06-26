moduledir=$(prefix)/modules
module_LTLIBRARIES = libmodauthopenid.la

datadir=$(prefix)
dist_data_DATA = README COPYING NEWS AUTHORS
EXTRA_DIST = UPGRADE

ACLOCAL_AMFLAGS = -I acinclude.d

INCLUDES = ${HTTPD_CFLAGS} ${APR_CFLAGS} ${OPKELE_CFLAGS} ${SQLITE3_CFLAGS} ${CURL_CFLAGS}
AM_LDFLAGS = ${OPKELE_LIBS} ${SQLITE3_LDFLAGS} ${CURL_LIBS} ${APR_LDFLAGS}

libmodauthopenid_la_SOURCES = mod_auth_openid.cpp MoidConsumer.cpp moid_utils.cpp http_helpers.cpp \
	SessionManager.cpp config.h  http_helpers.h  mod_auth_openid.h  MoidConsumer.h  moid_utils.h \
	SessionManager.h  types.h

install-data-hook:
	mkdir -p $(prefix)/modules && cd $(prefix)/modules && touch libmodauthopenid.so && ln -fs libmodauthopenid.so mod_auth_openid.so

