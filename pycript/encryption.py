from . import encoding, decoding
from .execution import execute_command


#Jsonvalueencrypt     -->   Parameterencrypt 

def Parameterencrypt(selectedlang, path, data,headers_str):
    output = execute_command(selectedlang, path, str(data),headers_str)

    if output is not False:
        return output.decode('utf-8')
    else:
        return data
