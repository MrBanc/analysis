#!/bin/bash
cat /dev/null > /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_syscalls_found
n_lines=$(cat /home/ben/Documents/unif/github/research/analysis/static/tests/scripts/get_syscalls_found.sh | grep "^/bin/" | wc -l)
i=1
for line in $(cat /home/ben/Documents/unif/github/research/analysis/static/tests/scripts/get_syscalls_found.sh  | grep "^/bin/")
do
    echo "$i/$n_lines: $line"
    result=$(timeout 120 python static_analyser.py --app $line -l f -v t -d f --csv f 2>&1 | grep "^Total number of syscalls:" | cut -d":" -f 2)
    # I know, there are two spaces like this... But I won't change it so that it is easier to compare with previous results
    echo "$line: $result" >> /home/ben/Documents/unif/github/research/analysis/static/tests/data/nb_syscalls_found
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
