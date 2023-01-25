import subprocess
from base64 import b64encode
import os


def Jsonvaluedecrypt(path,data):
    try:
        data2 = b64encode(data)
        path2 = os.path.abspath(path)
        if os.path.exists(path2):
            output = subprocess.check_output(["node", path2,"-d",data2])
            output = output.rstrip()
        else:
            output = data
    except subprocess.CalledProcessError:
    
        output = data
    return output    


def Customrequestdecrypt(path,header,body):
    try:
        body2 = b64encode(body)
        output = subprocess.check_output(["node", path,"-d",body2,"-h",header]).rstrip()
    except subprocess.CalledProcessError:
    
        output = body
    return output        