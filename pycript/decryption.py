import subprocess
from base64 import b64encode,b64decode



def Jsonvaluedecrypt(selectedlang, path,data):
    try:
        data2 = b64encode(data)

        if selectedlang == "JavaScript":
            output = subprocess.check_output(["node", path,"-d",data2]).rstrip()
        elif selectedlang == "Python":
            output = subprocess.check_output(["python", path,"-d",data2]).rstrip()
        elif selectedlang == "Java Jar":
              output = subprocess.check_output(["java", "-jar",path,"-d",data2]).rstrip()

    except subprocess.CalledProcessError:
    
        output = data
    return output    


def Customrequestdecrypt(selectedlang, path,header,body):
    try:
        body2 = b64encode(body)

        if selectedlang == "JavaScript":
            output = subprocess.check_output(["node", path,"-d",body2,"-h",header]).rstrip()
        elif selectedlang == "Python":
            output = subprocess.check_output(["python", path,"-d",body2,"-h",header]).rstrip()
        elif selectedlang == "Java Jar":
            output = subprocess.check_output(["java", "-jar",path,"-d",body2,"-h",header]).rstrip()
    except subprocess.CalledProcessError:
    
        output = body
    return output        



def Customeditrequestdecrypt(selectedlang, path,header,body):
    try:
        body2 = b64encode(body)
        header2 = b64encode(header)

        if selectedlang == "JavaScript":
            output = subprocess.check_output(["node", path, "-d", body2, "-h", header2])
        elif selectedlang == "Python":
            output = subprocess.check_output(["python", path, "-d", body2, "-h", header2])
        elif selectedlang == "Java Jar":
            output = subprocess.check_output(["java", "-jar",path, "-d", body2, "-h", header2])

        lines = output.splitlines()
        headerbase64 = lines[0]
        bodybase64 = lines[1]
      
        header = b64decode(headerbase64).decode('utf-8')
        body = b64decode(bodybase64).decode('utf-8')
    except subprocess.CalledProcessError:
    
        header = header
        body = body
    return (header,body)        
