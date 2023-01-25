import subprocess
from base64 import b64encode

def Jsonvalueencrypt(path,data):
    try:
        data = b64encode(data)
        output = subprocess.check_output(["node", path,"-d",str(data)]).rstrip()
    except subprocess.CalledProcessError:
    
        output = data
    return output 




def Customrequestencrypt(path,header,body):
    try:
        body = b64encode(body)
        output = subprocess.check_output(["node", path,"-d",body,"-h",header]).rstrip()
    except subprocess.CalledProcessError:
    
        output = body
    return output        