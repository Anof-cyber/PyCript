from .execution import execute_command
from .gethelpers import string_to_bytes, bytes_to_string

#Parameterdecrypt     -->   Parameterdecrypt 

def Parameterdecrypt(selectedlang, path, data,headers_str=None):
    body_parameter_byte = list(string_to_bytes(data))
    result = execute_command(selectedlang, path, body_parameter_byte,headers_str)
    if result is not False:
        body, header = result
        string_body = bytes_to_string(body)
        return string_body,header
    else:
        return data,headers_str




