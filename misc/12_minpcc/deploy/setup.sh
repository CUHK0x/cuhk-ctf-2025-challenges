#!/usr/bin/bash

function gen_tc() {
    local TC_DIR=$1
    for i in $(seq 1 $TC_COUNT)
    do
        local l_count=$(( ($RANDOM % 1000) + 1 ))
        local tc_file="$TC_DIR/${i}${TC_SUFFIX}"
        local tc_ans="$TC_DIR/${i}${ANS_SUFFIX}"
        echo "$l_count" > $tc_file
        for j in $(seq 1 $l_count)
        do
            local chance=$(( $RANDOM % 4 ))
            if [ $chance -eq 0 ]
            then
                echo -n $FLAG | sha256sum - | cut -d ' ' -f 1 >> $tc_file
                echo "YES" >> $tc_ans
            else
                head -c 1024 /dev/urandom | sha256sum - | cut -d ' ' -f 1 >> $tc_file
                echo "NO" >> $tc_ans
            fi
        done
    done
}

if ! [ -d $TC_DIR ]
then
    echo 'Generating testcases...'
    mkdir $TC_DIR
    gen_tc $TC_DIR
fi

echo 'Making directories...'
mkdir -m a=rwx -p $SUBMISSIONS_DIR
mkdir -m a=rwx -p $EXE_DIR
mkdir -m a=rwx -p $OUT_DIR

echo 'System ready.'
