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

def is_stop_line(line):
    return line[-2] == '-' and line[-1] == 'stop'

def is_done_line(line):
    return line[-2] == '-' and line[-1] == 'done'

def test_call_graph_stops():
    """Checks that when a function does not need to be analyzed deeper (marked
    as "stop" in the log), it indeed is not analyzed deeper.
    """

    with open(utils.log_dir_path + "lib_functions.log", "r",
              encoding="utf-8") as f:
        lines = f.readlines()

    for i in range(len(lines) - 1):
        current_line = lines[i].strip().split()
        next_line = lines[i + 1].strip().split()

        if is_stop_line(current_line):
            assert get_depth(next_line[0]) <= get_depth(current_line[0])

def test_call_graph_useful_analysis():
    """Checks that when a function is analyzed deeper, it results in a function
    actually being analyzed (otherwise, the analysis is useless).

    To check this, we check if there is always at least one function which is
    not marked after a function marked as "done".
    """

    with open(utils.log_dir_path + "lib_functions.log", "r",
              encoding="utf-8") as f:
        lines = f.readlines()

    for i in range(len(lines) - 1):
        line_done = lines[i].strip().split()

        analysis_is_useful = False

        if not is_done_line(line_done):
            continue

        j = 1
        while i + j < len(lines):
            line_below = lines[i + j].strip().split()
            if get_depth(line_below[0]) <= get_depth(line_done[0]):
                break
            if not (is_done_line(line_below) or is_stop_line(line_below)):
                analysis_is_useful = True
                break
            j += 1

        assert analysis_is_useful is True, f"Analysis of function " \
                f"{line_done[1]} at line {i+1} should have stopped."
