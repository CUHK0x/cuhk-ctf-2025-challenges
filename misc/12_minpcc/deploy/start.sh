#!/bin/sh

export SUBMISSIONS_DIR='./submissions'
export EXE_DIR='./prog'
export OUT_DIR='./out'
export TC_DIR='./tc'

export TIME_LIMIT='1s'
export TC_COUNT=10
export TC_SUFFIX='.tc'
export ANS_SUFFIX='.ans'

if [ -z $FLAG ]
then
    echo "Something is wrong. Contact challenge author.";
    exit 1
fi

./setup.sh
/usr/sbin/xinetd -dontfork
