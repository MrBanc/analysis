#!/bin/bash
cat /dev/null > /home/ben/Documents/unif/github/research/analysis/static/tests/nb_syscalls_found
n_lines=$(cat /home/ben/Documents/unif/github/research/analysis/static/tests/get_syscalls_found.sh | grep "^/bin/" | wc -l)
i=1
for line in $(cat /home/ben/Documents/unif/github/research/analysis/static/tests/get_syscalls_found.sh  | grep "^/bin/")
do
    echo "$i/$n_lines: $line"
    result=$(timeout 30 python static_analyser.py --app $line -l -v t -d f --csv f 2>&1 | grep "^Total number of syscalls:" | cut -d":" -f 2)
    echo "$line: $result" >> /home/ben/Documents/unif/github/research/analysis/static/tests/nb_syscalls_found
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