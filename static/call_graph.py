from dataclasses import dataclass
from typing import Set, List

from custom_exception import StaticAnalyserException
from library_analyser import FunLibInfo


@dataclass
class FunGraphInfo:
    analyzed_to_depth: int
    used_syscalls: Set(str)
    called_functions: List(FunLibInfo)

class CallGraph:
    """TODO"""

    def __init__(self, max_depth=10):
        if not isinstance(max_depth, int) or max_depth < 0:
            raise StaticAnalyserException("max_depth must be a positive "
                                          "integer.")

        self.__max_depth = max_depth

        # dict: concat(function name, "@", function lib) -> FunGraphInfo
        self.__functions = {}

    def need_to_analyze_deeper(self, function, to_depth=-1):
        """Returns true if the given function has not yet been analyzed to the
        given depth or to the maximum depth if no depth has been given.

        Parameters
        ----------
        function : FunLibInfo
            the function to check
        to_depth : int, optional
            the depth to check
        """

        self.__valid_function_parameter(function)
        if to_depth == -1:
            to_depth = self.__max_depth

        key = self.__get_key(function)
        return (key not in self.__functions
                or self.__functions[key].analyzed_to_depth < to_depth)

    def confirm_analyzed_depth(self, function, depth):
        """The caller confirms that the function given has been analyzed to at
        least the given depth. If the analyzed depth of this function in the
        graph is below the given value, it will thus be updated to reflect this
        confirmation (by updating it to the given value).

        Parameters
        ----------
        function : FunLibInfo
            the function that is claimed to have been analyzed
        depth : int
            the claimed value of the function's analyzed depth
        """

        self.__valid_function_parameter(function)

        key = self.__get_key(function)
        self.__functions[key].analyzed_to_depth = max(
                depth, self.__functions[key].analyzed_to_depth)

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
            to_key = self.__get_key(from_fun)

            self.__valid_function_parameter(to_f)
            self.__add_node(to_f)

            called_fun_min_depth = min(
                    self.__functions[to_key].analyzed_to_depth,
                    called_fun_min_depth)

            if to_f in (self.__functions[to_key].called_functions):
                continue
            self.__functions[to_key].called_functions.append(to_f)

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

        key = self.__get_key(function)
        return self.__functions[key].called_functions

    def register_syscalls(self, function, syscalls):
        """Add syscalls to the used syscalls of a function.

        Parameters
        ----------
        function : FunLibInfo
            function to add syscalls to
        syscalls : set of str
            the set of syscalls used by the function
        """

        key = self.__get_key(function)
        self.__functions[key].used_syscalls.update(syscalls)

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

        key = self.__get_key(function)
        return self.__functions[key].used_syscalls

    def get_max_depth(self):
        """Getter function for max_depth"""
        return self.__max_depth

    def __add_node(self, function):
        key = self.__get_key(function)
        if key in self.__functions:
            return

        self.__functions[key] = FunGraphInfo(analyzed_to_depth=0,
                                             used_syscalls=set(),
                                             called_functions=[])

    def __valid_function_parameter(self, function):
        if not isinstance(function, FunLibInfo):
            raise StaticAnalyserException("functions passed to call graph need"
                                          " to be instances of FunLibInfo.")

    def __get_key(self, function):
        return function.library_path + "@" + function.name
