#!/bin/bash
GET_N_FUNCTIONS_FOUND="t"
LIMIT_FUNCTIONS=11 # nb of binaries where to look for the number of functions found - 1
cat /dev/null > /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_syscalls_found
cat /dev/null > /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_functions_found
cat /dev/null > /home/ben/Documents/unif/github/research/analysis/static/tests/data/execution_time_syscalls_found
n_lines=$(cat /home/ben/Documents/unif/github/research/analysis/static/tests/scripts/get_syscalls_found.sh | grep "^/bin/" | wc -l)
i=1
for line in $(cat /home/ben/Documents/unif/github/research/analysis/static/tests/scripts/get_syscalls_found.sh  | grep "^/bin/")
do
    echo "$i/$n_lines: $line"
    result=$(/usr/bin/time -v timeout 600 python static_analyser.py --app $line -l $GET_N_FUNCTIONS_FOUND -v t -d f --csv f 2>&1 | sed -n -e '/^Total number of syscalls:/p' -e '/Elapsed (wall clock) time/p' | awk '{print $NF}' | awk 'BEGIN {RS=""; FS="\n"} { if (NF == 2) {printf("%s\telapsed time: %s", $1, $2)} else {printf("timeout\telapsed time: %s", $1)} }')
    echo -e "$line: $(echo $result | awk '{print $1}')" >> /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_syscalls_found
    echo -e "$line: $(echo $result | awk '{print $2, $3, $4}')" >> /home/ben/Documents/unif/github/research/analysis/static/tests/data/execution_time_syscalls_found
    if [ $GET_N_FUNCTIONS_FOUND == "t" ]
    then
        echo -e "$line: $(wc -l /home/ben/Documents/unif/github/research/analysis/logs/lib_functions.log | awk '{print $1}')" >> /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_functions_found
    fi
    ((i++))
    if [ $i -eq $LIMIT_FUNCTIONS ]
    then
        GET_N_FUNCTIONS_FOUND="f"
    fi
    sleep 1
done

exit

/bin/bash
/bin/newgidmap
/bin/pstree
/bin/gawk
/bin/make
/bin/ncat
/bin/ps
/bin/vulkaninfo
/bin/mariadb
/bin/ibus
/bin/VBoxClient
/bin/ssh
/bin/gamemode-simulate-game
/bin/wine64
/bin/zsh
/bin/docker
/bin/vlc
/bin/nvidia-powerd
/bin/nvidia-persistenced
/bin/nmap
