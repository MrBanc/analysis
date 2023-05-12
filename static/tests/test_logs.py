import sys
import os
from dataclasses import dataclass
from typing import List
# import subprocess

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import utils
from call_graph import CallGraph
from function_dataclasses import FunLibInfo

# subprocess.run(["python", "../static_analyser.py", "--app", "hw.strip", "-c",
#                 "False", "-d", "False", "-v", "False", "--log"], check=True)


class FunctionEntry:
    depth: int
    name: str


def get_depth(field1):
    """Return the depth as an int from the string of the first field of lines
    in the lib_functions.log file.
    """

    return int(field1[2:-1])

def test_call_graph_stops():
    """Checks that when a function does not need to be analyzed deeper (marked
    as "stop" in the log), it indeed is not analyzed deeper).
    """

    with open(utils.log_dir_path + "lib_functions.log", "r",
              encoding="utf-8") as f:
        lines = f.readlines()

    for i in range(len(lines) - 1):
        current_line = lines[i].strip().split()
        next_line = lines[i + 1].strip().split()

        if current_line[-2] == '-' and current_line[-1] == 'stop':
            assert get_depth(next_line[0]) <= get_depth(current_line[0])
