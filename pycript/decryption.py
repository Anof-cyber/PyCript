from . import encoding, decoding
from .execution import execute_command



def Jsonvaluedecrypt(selectedlang, path, data):
    data2 = encoding.encode_base64(data)
    output = execute_command(selectedlang, path, "-d", data2).decode('utf-8')
    return output

def Customrequestdecrypt(selectedlang, path, header, body):
    body2 = encoding.encode_base64(body)
    output = execute_command(selectedlang, path, "-d", body2, "-h", header).decode('utf-8')
    return output


def Customeditrequestdecrypt(selectedlang, path, header, body):
    body2 = encoding.encode_base64(body)
    header2 = encoding.encode_base64(header)
    
    output = execute_command(selectedlang, path, "-d", body2, "-h", header2)

    lines = output.splitlines()
    headerbase64, bodybase64 = lines[0], lines[1]
  
    header = decoding.decode_base64(headerbase64).decode('utf-8')
    body = decoding.decode_base64(bodybase64).decode('utf-8')

    return (header, body)      
