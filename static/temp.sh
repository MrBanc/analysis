#!/bin/zsh
rm -rf ~/logs_no_B
python static_analyser.py --app /bin/make -v t -c t -d t -w t -l t -s syscalls_map -f t -e t -A t -u y -m t
cp ../logs ~/logs_no_B -r
rm -rf ~/logs_B
python static_analyser.py --app /bin/make -v t -c t -d t -w t -l t -s syscalls_map -f t -e t -A t -u y -m t -B t
cp ../logs ~/logs_B -r
