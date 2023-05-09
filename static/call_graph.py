from function_dataclasses import FunLibInfo, FunGraphInfo
from custom_exception import StaticAnalyserException


# TODO: le fait que les fct demandent FunLibInfo en argument est pas ouf (par
# rapport au principes de l'OOP). On pourrait sûrement se contenter de donner
# le nom de la fonciton la plupart du temps, sinon faire plusieurs arguments
# avec les fields de la datastructure

class CallGraph:
    """TODO"""

    def __init__(self, max_depth=10):
        if not isinstance(max_depth, int) or max_depth < 0:
            raise StaticAnalyserException("max_depth must be a positive "
                                          "integer.")

        self.__max_depth = max_depth

        # dict: concat(function name, "@", function lib) -> FunGraphInfo
        self.__functions = {}

    # for debug purposes
    def __str__(self):
        ret_str = f"max depth: {self.__max_depth}\n"

        for key, value in self.__functions.items():
            ret_str += str(key) + " -> " + str(value) + "\n"

        return ret_str

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

    def register_calls(self, from_fun, to_funs):
        """Add calls (edges) to a function (node) in the graph.

        Parameters
        ----------
        from_fun : FunLibInfo
            function to add calls to
        to_funs : set of FunLibInfo (could also work with a list)
            functions to add to the called functions of `from_fun`
        """

        self.__valid_function_parameter(from_fun)

        from_key = self.__get_key(from_fun)
        if from_key not in self.__functions:
            self.__add_node(from_fun)

        for to_f in to_funs:
            to_key = self.__get_key(to_f)

            self.__valid_function_parameter(to_f)
            if to_key not in self.__functions:
                self.__add_node(to_f)

            if from_fun not in self.__functions[to_key].called_by:
                self.__functions[to_key].called_by.append(from_fun)

            if to_f not in self.__functions[from_key].called_functions:
                self.__functions[from_key].called_functions.append(to_f)

        self.__functions[from_key].analyzed_to_depth = (
                self.__compute_analyzed_depth(from_fun))
        self.__update_predecessors_depth(from_fun)

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
        return (key in self.__functions
                and self.__functions[key].analyzed_to_depth >= 1)

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
        if key not in self.__functions:
            return []

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
        if key not in self.__functions:
            self.__add_node(function)

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
        if key not in self.__functions:
            return set()

        return self.__functions[key].used_syscalls

    def get_max_depth(self):
        """Getter function for max_depth"""
        return self.__max_depth

    def __update_predecessors_depth(self, function):
        """Update the field `analyzed_to_depth` of the predecessors of the
        given function if needed.

        It is assumed that once a node with a value of the field that does not
        need an update is reached, there is no need to proceed further.

        Note: "predecessor" in a directed graph is the general term for
        "ancestor" within the context of a tree

        Parameters
        ----------
        function : FunLibInfo
            the function whose predecessors will be checked
        """

        self.__valid_function_parameter(function)

        key = self.__get_key(function)
        if key not in self.__functions:
            #TODO: may be a good idea to raise an exception as this should
            # never happen
            return

        # Note: "in-neighbor" in a directed graph is the general term for
        # "parent" within the context of a tree
        for in_neighbor in self.__functions[key].called_by:
            in_key = self.__get_key(in_neighbor)

            self.__valid_function_parameter(in_neighbor)
            if in_key not in self.__functions:
                #TODO: may be a good idea to raise an exception as this should
                # never happen
                continue

            new_analyzed_to_depth = self.__compute_analyzed_depth(in_neighbor)
            if (new_analyzed_to_depth
                == self.__functions[in_key].analyzed_to_depth):
                continue

            self.__functions[in_key].analyzed_to_depth = new_analyzed_to_depth
            self.__update_predecessors_depth(in_neighbor)

    def __compute_analyzed_depth(self, function):
        """Compute what should be the `analyzed_to_depth` value of the given
        function by looking at the registered called functions (ie. their
        out-neighbors)

        Parameter
        ---------
        function : FunLibInfo
            function whose field is computed

        Returns
        -------
        called_fun_min_depth : int
            what should be the `analyzed_to_depth` value of `function`
        """

        key = self.__get_key(function)
        if key not in self.__functions:
            #TODO: may be a good idea to raise an exception as this should
            # never happen
            return

        called_fun_min_depth = self.__max_depth

        for called_f in self.__functions[key].called_functions:
            called_key = self.__get_key(called_f)

            self.__valid_function_parameter(called_f)
            if called_key not in self.__functions:
                #TODO: may be a good idea to raise an exception as this should
                # never happen
                continue

            called_fun_min_depth = min(
                    self.__functions[called_key].analyzed_to_depth,
                    called_fun_min_depth)

        return min(called_fun_min_depth + 1, self.__max_depth)

    def __add_node(self, function):
        key = self.__get_key(function)

        self.__functions[key] = FunGraphInfo(analyzed_to_depth=0,
                                             used_syscalls=set(),
                                             called_functions=[],
                                             called_by=[])

    def __valid_function_parameter(self, function):
        if not isinstance(function, FunLibInfo):
            raise StaticAnalyserException("functions passed to call graph need"
                                          " to be instances of FunLibInfo.")

    def __get_key(self, function):
        return function.name + "@" + function.library_path
