

from .decryption import Jsonvaluedecrypt, Customrequestdecrypt
from .encryption import Jsonvalueencrypt, Customrequestencrypt
import json
from collections import OrderedDict


class Requestchecker():
    def __init__(self, extender, query, http_request_response):
        self._extender = extender
        self._selectedmessage = query
        self.message = http_request_response

    def encryptstring(self):
        if self._extender.selectedrequst == True:
            self.myrequest = self._extender.helpers.analyzeRequest(
                self.message.getRequest())
            self.header = self.myrequest.getHeaders()
            
        else:
            pass

        if str(self._extender.selectedrequesttpye) == "Custom Request":

            encrypted = Customrequestencrypt(
                self._extender.encryptionfilepath, str(self.header), self._selectedmessage)
            return encrypted

        else:
            encrypted = Jsonvalueencrypt(
                self._extender.encryptionfilepath, self._selectedmessage)
            return encrypted

    def decryptstring(self):
        if self._extender.selectedrequst == True:
            self.myrequest = self._extender.helpers.analyzeRequest(
                self.message.getRequest())
            self.header = self.myrequest.getHeaders()
           
        else:
            pass

        if str(self._extender.selectedrequesttpye) == "Custom Request":

            decrypted = Customrequestdecrypt(
                self._extender.decryptionfilepath, str(self.header), self._selectedmessage)
            return decrypted

        else:
            decrypted = Jsonvaluedecrypt(
                self._extender.decryptionfilepath, self._selectedmessage)
            return decrypted


def DecryptRequest(extender, stringbody, header):

    decryptionpath = extender.decryptionfilepath
    mynewjson = OrderedDict()
    if str(extender.selectedrequesttpye) == "Whole Body (JSON)":
        decryptedvalue = Jsonvaluedecrypt(decryptionpath, stringbody)
        output = extender.helpers.stringToBytes(decryptedvalue)
        return extender.helpers.buildHttpMessage(header, output)

    elif str(extender.selectedrequesttpye) == "JSON Value":

        try:
            json_object = json.loads(stringbody)
            for key, value in json_object.items():
                decryptedvalue = Jsonvaluedecrypt(decryptionpath, value)
                mynewjson[key] = decryptedvalue
            output = extender.helpers.stringToBytes(json.dumps(mynewjson))
            return extender.helpers.buildHttpMessage(header, output)

        except ValueError:
            return extender.helpers.buildHttpMessage(header, stringbody)

    elif str(extender.selectedrequesttpye) == "JSON Key & Value":
        try:
            json_object = json.loads(stringbody)
            for key, value in json_object.items():
                decryptedkey = Jsonvaluedecrypt(decryptionpath, key)
                decryptedvalue = Jsonvaluedecrypt(decryptionpath, value)
                mynewjson[decryptedkey] = decryptedvalue
            output = extender.helpers.stringToBytes(json.dumps(mynewjson))
            return extender.helpers.buildHttpMessage(header, output)
        except ValueError:
            return extender.helpers.buildHttpMessage(header, stringbody)

    elif str(extender.selectedrequesttpye) == "Custom Body":
        decryptedvalue = Jsonvaluedecrypt(decryptionpath, stringbody)
        output = extender.helpers.stringToBytes(decryptedvalue)
        return extender.helpers.buildHttpMessage(header, output)

    elif str(extender.selectedrequesttpye) == "Custom Request":

        extender.callbacks.printOutput(str(header))
        output = Customrequestdecrypt(decryptionpath, str(header), stringbody)
        return extender.helpers.buildHttpMessage(header, output)

    else:
        return extender.helpers.buildHttpMessage(header, stringbody)




def EncryptRequest(extender, stringbody, header):
    encryptionpath = extender.encryptionfilepath
    mynewjson = OrderedDict()

    if str(extender.selectedrequesttpye) == "Whole Body (JSON)":
        encryptedvalue = Jsonvalueencrypt(encryptionpath, stringbody)
        output = extender.helpers.stringToBytes(encryptedvalue)
        return extender.helpers.buildHttpMessage(header, output)
    

    elif str(extender.selectedrequesttpye) == "JSON Value":

        try:
            json_object = json.loads(stringbody)
            for key, value in json_object.items():
                encrytpedvalue = Jsonvalueencrypt(encryptionpath, value)
                mynewjson[key] = encrytpedvalue
            output = extender.helpers.stringToBytes(json.dumps(mynewjson))
            return extender.helpers.buildHttpMessage(header, output)

        except ValueError:
            return extender.helpers.buildHttpMessage(header, stringbody)
        
    elif str(extender.selectedrequesttpye) == "JSON Key & Value":
        try:
            json_object = json.loads(stringbody)
            for key, value in json_object.items():
                encryptedkey = Jsonvalueencrypt(encryptionpath, key)
                encryptedvalue = Jsonvalueencrypt(encryptionpath, value)
                mynewjson[encryptedkey] = encryptedvalue
            output = extender.helpers.stringToBytes(json.dumps(mynewjson))
            return extender.helpers.buildHttpMessage(header, output)
        except ValueError:
            return extender.helpers.buildHttpMessage(header, stringbody)
        


    elif str(extender.selectedrequesttpye) == "Custom Body":
        enccryptedvalue = Jsonvalueencrypt(encryptionpath, stringbody)
        output = extender.helpers.stringToBytes(enccryptedvalue)
        return extender.helpers.buildHttpMessage(header, output)
    

    elif str(extender.selectedrequesttpye) == "Custom Request":

        extender.callbacks.printOutput(str(header))
        output = Customrequestencrypt(encryptionpath, str(header), stringbody)
        return extender.helpers.buildHttpMessage(header, output)

    else:
        return extender.helpers.buildHttpMessage(header, stringbody)


        


