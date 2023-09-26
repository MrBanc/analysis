#!/bin/bash
n_lines=$(ls -1 /bin | wc -l)
i=1
for line in $(ls -1 /bin)
do
    echo "$i/$n_lines: $line"
    timeout 30 python static_analyser.py --app /bin/$line -v f -d f --csv f 2>&1 | grep "Multiple"
    if [[ $? -eq 0 ]]
    then
        echo "/bin/$line" >> /home/ben/Documents/unif/github/research/analysis/static/tests/data/have_name_clash
    fi
    ((i++))
    sleep 1
done
