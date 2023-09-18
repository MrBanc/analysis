"""
Exception class for the static analyser.
"""

class StaticAnalyserException(Exception):
    """Exception class for the static analyser"""
    def __init__(self, message, is_critical=True):
        super().__init__(message)
        self.is_critical = is_critical
