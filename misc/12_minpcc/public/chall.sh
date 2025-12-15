#!/usr/bin/bash

cd $(dirname $0)

set -u

cat <<'EOT'
===================================================

  __  __ _____ _   _ _____   _____ _____ 
 |  \/  |_   _| \ | |  __ \ / ____/ ____|
 | \  / | | | |  \| | |__) | |   | |     
 | |\/| | | | | . ` |  ___/| |   | |     
 | |  | |_| |_| |\  | |    | |___| |____ 
 |_|  |_|_____|_| \_|_|     \_____\_____|

MinPCC: Minimalistic Programming Challenge Checker
===================================================
Shell scripts are all you need!

Enter your C source file: (Type "EOF" in one line to end the file)
EOT

SRC=''
while IFS= read line
do
    if [[ $line != 'EOF' ]]
    then
        SRC="$SRC$line"$'\n'
    else
        break
    fi
done
SRC_ID=$(echo "$SRC" | sha256sum - | cut -d ' ' -f 1)
SRC_PATH=$SUBMISSIONS_DIR/$SRC_ID.c
if [ -e $SRC_PATH ]
then
    echo -e "\x1b[93mThis file has already been submitted!\x1b[0m"
    echo -e "Verdict: \x1b[31mSubmission rejected\x1b[0m"
    exit 0
fi
echo "$SRC" > $SRC_PATH

EXE_PATH=$EXE_DIR/$SRC_ID
if ! timeout 2s gcc -nostartfiles entrypoint.c "$SRC_PATH" -o "$EXE_PATH"
then
    echo -e "Verdict: \x1b[31mCompilation Error\x1b[0m"
    exit 0
fi

PROG_OUT=$OUT_DIR/$SRC_ID.out
for i in $(seq 1 $TC_COUNT)
do
    echo "Running Test ${i}..."
    timeout -k "$TIME_LIMIT" "$TIME_LIMIT" "$EXE_PATH" < "$TC_DIR/${i}${TC_SUFFIX}" &> "$PROG_OUT"
    case $? in
        124)
            echo -e "Verdict: \x1b[31mTime Limit Exceeded\x1b[0m"
            exit 0
            ;;
        159)
            echo -e "Verdict: \x1b[31mSecurity Violation\x1b[0m"
            exit 0
            ;;
        *)
            ;;
    esac
    if ! diff "$PROG_OUT" "${TC_DIR}/${i}${ANS_SUFFIX}" &> /dev/null
    then
        echo -e "Verdict: \x1b[31mWrong Answer\x1b[0m"
        exit 0
    fi
done

echo -e "Verdict: \x1b[32mAccepted\x1b[0m"
exit 0
