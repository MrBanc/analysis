#!/bin/bash
n_lines=$(cat /home/ben/Documents/unif/github/research/analysis/static/tests/data/use_dlopen | grep "^/bin/" | wc -l)
i=1
for line in $(cat /home/ben/Documents/unif/github/research/analysis/static/tests/data/use_dlopen  | grep "^/bin/")
do
    echo "$i/$n_lines: $line"
    timeout 30 python static_analyser.py --app $line -l -v f -d f --csv f 2>&1 | grep "gougoug"
    ((i++))
    sleep 1
done
