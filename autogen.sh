#! /bin/sh
libtoolize="$(type -P glibtoolize || type -P libtoolize)"
$libtoolize -f -c && aclocal -I ./acinclude.d && autoheader && automake -ac && autoconf
