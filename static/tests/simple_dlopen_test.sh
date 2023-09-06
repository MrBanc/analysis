#!/bin/bash
n_lines=$(cat /home/ben/Documents/unif/github/impSyscall/code/analysis/static/tests/use_ldopen | grep "^/bin/" | wc -l)
i=1
for line in $(cat /home/ben/Documents/unif/github/impSyscall/code/analysis/static/tests/use_ldopen | grep "^/bin/")
do
    echo "$i/$n_lines: $line"
    timeout 30 python static_analyser.py --app $line -v f -d f --csv f 2> /dev/null
    ((i++))
    sleep 1
done

