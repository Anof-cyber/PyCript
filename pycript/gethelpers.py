from java.util import Arrays;
from java.lang import String
import re

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
    s = str(byte_data)
    numbers = re.findall(r'\d+', s)
    return ''.join(chr(int(n) & 0xFF) for n in numbers)
