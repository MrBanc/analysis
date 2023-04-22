from dataclasses import dataclass
from custom_exception import StaticAnalyserException
from library_analyser import FunLibInfo


@dataclass
class FunGraphInfo:
    identifier: int
    analyzed_to_depth: int

class CallGraph:
    """TODO"""

    def __init__(self, MAX_DEPTH=10):
        if not isinstance(MAX_DEPTH, int) or MAX_DEPTH < 0:
            raise StaticAnalyserException("MAX_DEPTH must be a positive "
                                          "integer.")

        self.__MAX_DEPTH = MAX_DEPTH

        # dict: concat(function name, "@", function lib) -> FunGraphInfo
        self.__functions = {}

        # represented as an adjacency list
        self.__graph = []

    def need_to_analyze_deeper(self, function):
        self.__valid_function_parameter(function)

        key = self.__get_key(function)
        return (key in self.functions
                and self.functions[key].analyzed_to_depth == self.__MAX_DEPTH)

    def add_calls(self, from_fun, to_funs):
        """add edge in the graph (TODO)"""
        called_fun_min_depth = 0

        self.__valid_function_parameter(from_fun)
        self.__add_node(from_fun)
        for to_f in to_funs:
            self.__valid_function_parameter(to_f)
            self.__add_node(to_f)

            called_fun_min_depth = min(
                    self.functions[self.__get_key(to_f)].analyzed_to_depth,
                    called_fun_min_depth)

            if self.__get_id(to_f) in self.__graph[self.__get_id(from_fun)]:
                continue
            self.__graph[self.__get_id(from_fun)].append(self.__get_id(to_f))

        self.__functions[self.__get_key(from_fun)].analyzed_to_depth = (
                called_fun_min_depth + 1)

    def __add_node(self, function):
        key = self.__get_key(function)
        if key in self.functions:
            return

        self.functions[key] = FunGraphInfo(identifier=len(self.graph),
                                           analyzed_to_depth=0)

        self.__graph.append([])

    def __valid_function_parameter(self, function):
        if not isinstance(function, FunLibInfo):
            raise StaticAnalyserException("functions passed to call graph need"
                                          " to be instances of FunLibInfo.")

    def __get_key(self, function):
        return function.library_path + "@" + function.name

    def __get_id(self, function):
        return self.__functions[self.__get_key(function)].identifier
