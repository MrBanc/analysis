from dataclasses import dataclass
from typing import Set

from custom_exception import StaticAnalyserException
from library_analyser import FunLibInfo


@dataclass
class FunGraphInfo:
    identifier: int
    analyzed_to_depth: int
    used_syscalls: Set(str)

class CallGraph:
    """TODO"""

    def __init__(self, max_depth=10):
        if not isinstance(max_depth, int) or max_depth < 0:
            raise StaticAnalyserException("max_depth must be a positive "
                                          "integer.")

        self.__max_depth = max_depth

        # dict: concat(function name, "@", function lib) -> FunGraphInfo
        self.__functions = {}

        # represented as an adjacency list
        self.__graph = []

    def need_to_analyze_deeper(self, function):
        self.__valid_function_parameter(function)

        key = self.__get_key(function)
        return not (key in self.__functions
                    and self.__functions[key].analyzed_to_depth
                        >= self.__max_depth)

    def register_calls(self, from_fun, to_funs):
        """Add calls (edges) to a function (node) in the graph.

        Parameters
        ----------
        from_fun : FunLibInfo
            function to add calls to
        to_funs : set of FunLibInfo (could also work with a list)
            functions to add to the called functions of `from_fun`
        """

        called_fun_min_depth = 0

        self.__valid_function_parameter(from_fun)
        self.__add_node(from_fun)
        for to_f in to_funs:
            self.__valid_function_parameter(to_f)
            self.__add_node(to_f)

            called_fun_min_depth = min(
                    self.__functions[self.__get_key(to_f)].analyzed_to_depth,
                    called_fun_min_depth)

            if to_f in self.__graph[self.__get_id(from_fun)]:
                continue
            self.__graph[self.__get_id(from_fun)].append(to_f)

        self.__functions[self.__get_key(from_fun)].analyzed_to_depth = (
                called_fun_min_depth + 1)

    def calls_registered(self, function):
        """Returns true if calls have already been registered to the given
        function (meaning the analyzed depth is at least 1)

        Parameters
        ----------
        function : FunLibInfo
            function to check

        Returns
        -------
        calls_registered : bool
            True if calls have already been registered
        """

        self.__valid_function_parameter(function)

        key = self.__get_key(function)
        return self.__functions[key].analyzed_to_depth >= 1

    def get_called_funs(self, function):
        """Get the functions called by the given function

        Parameters
        ----------
        function : FunLibInfo
            function to get calls from

        Returns
        -------
        calls : list of FunLibInfo
            functions called by the given function
        """

        return self.__graph[self.__get_id(function)]

    def register_syscalls(self, function, syscalls):
        """Add syscalls to the used syscalls of a function.

        Parameters
        ----------
        function : FunLibInfo
            function to add syscalls to
        syscalls : set of str
            the set of syscalls used by the function
        """

        (self.__functions[self.__get_key(function)].used_syscalls
         .update(syscalls))

    def get_registered_syscalls(self, function):
        """Get the (registered) set of syscalls used by the given function.

        Parameters
        ----------
        function : FunLibInfo
            function to get syscalls from

        Returns
        -------
        used_syscalls : set of str
            the (registered) set of syscalls used
        """

        return self.__functions[self.__get_key(function)].used_syscalls

    def __add_node(self, function):
        key = self.__get_key(function)
        if key in self.__functions:
            return

        self.__functions[key] = FunGraphInfo(identifier=len(self.__graph),
                                             analyzed_to_depth=0,
                                             used_syscalls = set())

        self.__graph.append([])

    def __valid_function_parameter(self, function):
        if not isinstance(function, FunLibInfo):
            raise StaticAnalyserException("functions passed to call graph need"
                                          " to be instances of FunLibInfo.")

    def __get_key(self, function):
        return function.library_path + "@" + function.name

    def __get_id(self, function):
        return self.__functions[self.__get_key(function)].identifier
