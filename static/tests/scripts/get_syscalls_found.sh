#!/bin/bash
cat /dev/null > /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_syscalls_found
n_lines=$(cat /home/ben/Documents/unif/github/research/analysis/static/tests/scripts/get_syscalls_found.sh | grep "^/bin/" | wc -l)
i=1
for line in $(cat /home/ben/Documents/unif/github/research/analysis/static/tests/scripts/get_syscalls_found.sh  | grep "^/bin/")
do
    echo "$i/$n_lines: $line"
    result=$(/usr/bin/time -v timeout 600 python static_analyser.py --app $line -l f -v t -d f --csv f 2>&1 | sed -n -e '/^Total number of syscalls:/p' -e '/Elapsed (wall clock) time/p' | awk '{print $NF}' | awk 'BEGIN {RS=""; FS="\n"} { printf("%s\telapsed time: %s", $1, $2) }')
    echo -e "$line: $result" >> /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_syscalls_found
    ((i++))
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
