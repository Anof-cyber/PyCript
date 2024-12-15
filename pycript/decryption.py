from . import encoding, decoding
from .execution import execute_command


#Parameterdecrypt     -->   Parameterdecrypt 

def Parameterdecrypt(selectedlang, path, data,headers_str):
    #data2 = encoding.encode_base64(data)
    body, header = execute_command(selectedlang, path, data,headers_str)
    if body is not False:
        return body,header
    else:
        return data,headers_str
