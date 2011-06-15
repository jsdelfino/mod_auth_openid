AC_INIT([mod_auth_openid], [0.5], [bmuller@butterfat.net])
AC_DEFINE([PACKAGE_URL],["http://trac.butterfat.net/public/mod_auth_openid"],[project url])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE()

AC_CONFIG_MACRO_DIR([acinclude.d])

AC_PROG_CXX
AC_PROG_CXXCPP
AC_LANG_CPLUSPLUS
AC_CANONICAL_HOST
AC_PROG_INSTALL
AM_PROG_LIBTOOL

AC_HEADER_STDC

# provide flag --enable-debug
AC_ARG_ENABLE(debug, AC_HELP_STRING([[--enable-debug]], [enable debugging output to Apache error log]),
[if test "$enableval" = "yes"; then
    DEBUG="yes"
    CPPFLAGS="$CPPFLAGS -DDEBUG"
fi]
)

cppflags="${CPPFLAGS}"
defaultlibs="${LIBS}"

# Configure path to Apache APR and HTTPD includes and libs.
AC_MSG_CHECKING([for apr])
AC_ARG_WITH([apr], [AC_HELP_STRING([--with-apr=PATH], [path to installed Apache APR [default=/usr]])], [
  APR_CFLAGS="-I${withval}/include/apr-2"
  APR_LDFLAGS="-L${withval}/lib -R${withval}/lib -lapr-2"
  AC_MSG_RESULT("${withval}")
], [
  APR_CFLAGS="-I/usr/include/apr-2"
  APR_LDFLAGS="-lapr-2"
  AC_MSG_RESULT(/usr)
])
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_LDFLAGS)
LIBS="${APR_LDFLAGS} ${defaultlibs}"
AC_CHECK_LIB([apr-2], [apr_pool_initialize], [], [AC_MSG_ERROR([couldn't find a suitable libapr-2, use --with-apr=PATH])])

AC_MSG_CHECKING([for httpd])
AC_ARG_WITH([httpd], [AC_HELP_STRING([--with-httpd=PATH], [path to installed Apache HTTPD [default=/usr]])], [
  HTTPD_CFLAGS="-I${withval}/include"
  AC_MSG_RESULT("${withval}")
], [
  HTTPD_CFLAGS="-I/usr/include/apache2"
  AC_MSG_RESULT(/usr)
])
AC_SUBST(HTTPD_CFLAGS)

# Check for libopkele
AC_MSG_CHECKING([for libopkele])
AC_ARG_WITH([libopkele], [AC_HELP_STRING([--with-libopkele=PATH], [path to installed libopkele [default=/usr]])], [
  OPKELE_CFLAGS="-I${withval}/include"
  OPKELE_LIBS="-L${withval}/lib -R${withval}/lib -lopkele"
  AC_MSG_RESULT("${withval}")
], [
  OPKELE_CFLAGS=""
  OPKELE_LIBS="-lopkele"
  AC_MSG_RESULT(/usr)
])
AC_SUBST(OPKELE_CFLAGS)
AC_SUBST(OPKELE_LIBS)
CPPFLAGS="${OPKELE_CFLAGS}"
AC_CHECK_HEADER([opkele/opkele-config.h], [], [AC_MSG_ERROR([couldn't find a suitable libopkele library, use --with-libopkele=PATH])])
LIBS="${OPKELE_LIBS} ${defaultlibs}"
#AC_CHECK_LIB([opkele], [_init], [], [AC_MSG_ERROR([couldn't find a suitable libopkele library, use --with-libopkele=PATH])])

# Check for curl
AC_MSG_CHECKING([for curl])
AC_ARG_WITH([curl], [AC_HELP_STRING([--with-curl=PATH], [path to installed curl [default=/usr]])], [
  CURL_CFLAGS="-I${withval}/include"
  CURL_LIBS="-L${withval}/lib -R${withval}/lib -lcurl"
  AC_MSG_RESULT("${withval}")
], [
  CURL_CFLAGS=""
  CURL_LIBS="-lcurl"
  AC_MSG_RESULT(/usr)
])
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)
CPPFLAGS="${CURL_CFLAGS}"
AC_CHECK_HEADER([curl/curl.h], [], [AC_MSG_ERROR([couldn't find a suitable curl library, use --with-curl=PATH])])
LIBS="${CURL_LIBS}"
AC_CHECK_LIB([curl], [curl_global_init], [], [AC_MSG_ERROR([couldn't find a suitable curl library, use --with-curl=PATH])])

CPPFLAGS="${cppflags}"
LIBS="${defaultlibs}"

# Idea taken from libopekele
nitpick=false
AC_ARG_ENABLE([nitpicking],
 AC_HELP_STRING([--enable-nitpicking],[make compiler somewhat overly fastidious about the code it deals with]),
 [ test "$enableval" = "no" || nitpick=true ]
)
if $nitpick ; then
 CPP_NITPICK="-Wall -Wextra -Wundef -Wshadow -Wunsafe-loop-optimizations -Wconversion -Wmissing-format-attribute"
 CPP_NITPICK="$CPP_NITPICK -Wredundant-decls -ansi -Wmissing-noreturn"
 CPPFLAGS="$CPPFLAGS $CPP_NITPICK"
# CFLAGS="$CFLAGS $CPP_NITPICK"
# CXXFLAGS="$CXXFLAGS $CPP_NITPICK"
fi

AC_CONFIG_FILES([
 Makefile
])
AC_OUTPUT

echo " ***"
echo " *** You are now ready to build mod_auth_openid:"
echo " *** Enter the following commands:"
echo " ***"
echo " *** $> make"
echo " *** $> su root"
echo " *** $> make install"
echo " ***"
echo " *** Report bugs at http://trac.butterfat.net/public/mod_auth_openid"
echo " *** Thanks for using free (as in speech and beer) software."
echo " ***"
echo
