#!/bin/bash
if [[ $(cat ../logs/lib_functions.log | sed '/ - done$/d' | sed -n '/D-[0-9]*:/p' | sed 's/ *D-[0-9]*: //' | sort | uniq -d) ]]
then
    echo "[ERROR] Some functions were analysed mutliple times."
else
    echo "[SUCCESS] No duplicate function analysis found (for the current lib_functions.log)"
fi
