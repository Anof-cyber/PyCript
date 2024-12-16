from java.util import Arrays;
from java.lang import String

_helpers = None  # Private variable to hold the helpers reference.

def set_helpers(helpers):
    """Set the helpers instance."""
    global _helpers
    _helpers = helpers

def get_helpers():
    """Get the helpers instance."""
    if _helpers is None:
        raise RuntimeError("Helpers not initialized. Call `set_helpers` first.")
    return _helpers

def string_to_bytes(string):
    """Convert a string to bytes using helpers."""
    return get_helpers().stringToBytes(string)

def bytes_to_string(byte_data):
    """Convert bytes to string using helpers."""
    byte_data_clean = byte_data.strip('[]')
    byte_data2 = [int(code.strip()) for code in byte_data_clean.split(',')]
    #return get_helpers().bytesToString(byte_data2)   # for some reason helper API gives error or remove some non ascii data from string results in wrong string for non ascii or binary data
    return ''.join(chr(code) for code in byte_data2)
