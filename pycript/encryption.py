from . import encoding, decoding
from .execution import execute_command


#Jsonvalueencrypt     -->   Parameterencrypt 

def Parameterencrypt(selectedlang, path, data):
    data = encoding.encode_base64(data)
    output = execute_command(selectedlang, path, str(data)).decode('utf-8')
    return output


def Customrequestencrypt(selectedlang, path, header, body):
    body = encoding.encode_base64(body)
    output = execute_command(selectedlang, path, body, header).decode('utf-8')
    return output
    

def Customeditrequestencrypt(selectedlang, path, header, body):
    body2 = encoding.encode_base64(body)
    header2 = encoding.encode_base64(header)
    
    output = execute_command(selectedlang, path, body2, header2)

    lines = output.splitlines()
    headerbase64, bodybase64 = lines[0], lines[1]
  
    header = decoding.decode_base64(headerbase64).decode('utf-8')
    body = decoding.decode_base64(bodybase64).decode('utf-8')

    return (header, body)
   