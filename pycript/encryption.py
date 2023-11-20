from . import encoding, decoding
from .execution import execute_command


#Jsonvalueencrypt     -->   Parameterencrypt 

def Parameterencrypt(selectedlang, path, data):
    output = execute_command(selectedlang, path, str(encoding.encode_base64(data)))

    if output is not False:
        return output.decode('utf-8')
    else:
        return data


def Customrequestencrypt(selectedlang, path, header, body):
    output = execute_command(selectedlang, path, encoding.encode_base64(body), encoding.encode_base64(header))
    
    if output is not False:
        return output.decode('utf-8')
    else:
        return body
    
    

def Customeditrequestencrypt(selectedlang, path, header, body):
    body2 = encoding.encode_base64(body)
    header2 = encoding.encode_base64(header)
    
    output = execute_command(selectedlang, path, body2, header2)
    if output is not False:
        lines = output.splitlines()
        headerbase64, bodybase64 = lines[0], lines[1]
        header = decoding.decode_base64(headerbase64).decode('utf-8')
        body = decoding.decode_base64(bodybase64).decode('utf-8')
        return (header, body)
    else:
        return (header, body)

   