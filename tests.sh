#!/bin/bash

DIR=$(pwd)
nginx_fname=$(ls -1 $DIR/install/*.tar.gz)

[ -d install/tmp ] || mkdir install/tmp
tar zxf $nginx_fname -C install/tmp

folder="$(ls -1 $DIR/install/tmp | grep nginx)"

export PATH=$DIR/install/tmp/$folder/sbin:$PATH
export LD_LIBRARY_PATH=$DIR/install/tmp/$folder/lib

export LUA_CPATH=$DIR/install/tmp/$folder/lib/lua/5.1/cjson.so
export LUA_PATH="$DIR/install/tmp/$folder/lib/?.lua;;"

ret=0

cd t

for t in $(find . -name *.t)
do
  echo "Tests : "$t
  export TEST_NGINX_SERVROOT=$DIR/results/$t/servroot
  export TEST_NGINX_ERROR_LOG=$DIR/results/$t/error.log
  [ -d "$TEST_NGINX_SERVROOT" ] && /usr/bin/rm -rf $TEST_NGINX_SERVROOT
  mkdir -p $TEST_NGINX_SERVROOT
  prove $t
  if [ $? -ne 0 ]; then
    ret=$?
    exit $ret
  fi
done

cd ..

rm -rf t/servroot
rm -rf install/tmp

exit $ret