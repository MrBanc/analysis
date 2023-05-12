import sys
import os

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from call_graph import CallGraph
from custom_exception import StaticAnalyserException
from function_dataclasses import FunLibInfo, FunGraphInfo


f1 = FunLibInfo(name="f1", library_path="/l", boundaries=[0,1])
f2 = FunLibInfo(name="f2", library_path="/l", boundaries=[0,1])
f3 = FunLibInfo(name="f3", library_path="/l", boundaries=[0,1])
f4 = FunLibInfo(name="f4", library_path="/l", boundaries=[0,1])
f5 = FunLibInfo(name="f5", library_path="/l", boundaries=[0,1])


def test_create():
    """Testing CallGraph constructor"""

    CallGraph()

    cg = CallGraph(34)
    assert 34 == cg.get_max_depth()

    with pytest.raises(StaticAnalyserException):
        CallGraph(-5)

def test_very_simple_graph():
    """
    f1 -> [f2, f3]
    f2 -> []
    f3 -> []
    """

    cg = CallGraph()

    assert cg.calls_registered(f1) is False

    assert cg.need_to_analyze_deeper(f1) is True

    cg.register_calls(f1, [f2, f3])

    assert cg.calls_registered(f1) is True
    assert cg.calls_registered(f2) is False

    assert cg.need_to_analyze_deeper(f1) is True
    assert cg.need_to_analyze_deeper(f2) is True

    cg.register_calls(f2, [])

    assert cg.calls_registered(f1) is True
    assert cg.calls_registered(f2) is True
    assert cg.calls_registered(f3) is False

    assert cg.need_to_analyze_deeper(f1) is True
    assert cg.need_to_analyze_deeper(f2) is False
    assert cg.need_to_analyze_deeper(f3) is True

    cg.register_calls(f3, [])

    assert cg.calls_registered(f1) is True
    assert cg.calls_registered(f2) is True
    assert cg.calls_registered(f3) is True

    assert cg.need_to_analyze_deeper(f1) is False
    assert cg.need_to_analyze_deeper(f2) is False
    assert cg.need_to_analyze_deeper(f3) is False

    assert cg.get_called_funs(f1) == [f2, f3]
    assert cg.get_called_funs(f2) == []
    assert cg.get_called_funs(f3) == []

def test_deep_graph():
    """
    f1 -> [f2]
    f2 -> [f3]
    f3 -> [f4]
    f4 -> [f5]
    f5 -> unknown
    """

    cg = CallGraph(2)

    funs = [f1, f2, f3, f4, f5]
    for i in range(len(funs) - 1):
        cg.register_calls(funs[i], [funs[i+1]])

    assert cg.need_to_analyze_deeper(f1) is False
    assert cg.need_to_analyze_deeper(f2) is False
    assert cg.need_to_analyze_deeper(f3) is False
    assert cg.need_to_analyze_deeper(f4) is True
    assert cg.need_to_analyze_deeper(f5) is True

def test_simple_graph_with_loop():
    """
    f1 -> [f2]
    f2 -> [f3]
    f3 -> [f4]
    f4 -> [f5]
    f5 -> [f2]
    """

    cg = CallGraph(10)

    funs = [f1, f2, f3, f4, f5]
    for i in range(len(funs) - 1):
        cg.register_calls(funs[i], [funs[i+1]])

    cg.register_calls(funs[-1], [funs[1]])

    for f in funs:
        assert cg.need_to_analyze_deeper(f) is False
