import os



'''
replace: 
    output = extender.helpers.stringToBytes(decryptedvalue)
    extender.helpers.buildHttpMessage(header, output)
because it's only support ascii.
'''
def buildHttpMessageForNoneASCII(header, body):
    tmp = b''    
    try:
        for item in header:
            tmp += item.encode("utf-8") + os.linesep.encode("utf-8")

        tmp += os.linesep.encode("utf-8") + body
    except Exception as e:
        pass
    return tmp
    

def stringToBytes(buff):
    return buff.encode("utf-8")