#!/bin/bash

start=0
if [ -f $1 ];then
    cat $1 | while read line
    do
        if echo $line | grep -q -E '\*\*\*\*Persistent Points-To Cache Statistics:'; then
            break
        fi
        if [ $start == 1 ]; then
            if [ -z "$line" ];then
                start=0
            elif [ "$line" = "!!!has no targets!!!" ]; then
                bb=""
            else
                echo $bb","$line >> $2"/BBinCalls.txt"
            fi
        fi
        if echo $line | grep -q -E 'Location:[[:space:]]\{'; then
            ln=$(echo $line | sed 's/.*Location:[[:space:]]{[[:space:]]ln:[[:space:]]\(.*\)[[:space:]]cl:[[:space:]]\(.*\)[[:space:]]fl:[[:space:]]\(.*\)[[:space:]]}.*/\1/g')
            fn=$(echo $line | sed 's/.*Location: { ln: \(.*\) cl: \(.*\) fl: \(.*\) }.*/\3/g')
            bb=${fn##*/}":"$ln
            # echo $line
            start=1
        fi
    done
fi