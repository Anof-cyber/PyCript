from burp import IMessageEditorTab
import json
from .decryption import Jsonvaluedecrypt,Customrequestdecrypt
from .encryption import Jsonvalueencrypt,Customrequestencrypt
from collections import OrderedDict

class CriptInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._txtInput = extender.callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self.controller = controller
        
        extender.callbacks.customizeUiComponent(self._txtInput.getComponent())


    def getTabCaption(self):
        return "PyCript"   


    def getUiComponent(self):
        
        return self._txtInput.getComponent()


    def isEnabled(self, content, isRequest):
        if content and isRequest:
            if str(self._extender.selectedrequesttpye) == "None":
                return False

            else:
                request = self._extender.helpers.analyzeRequest(self.controller.getHttpService(),self.controller.getRequest())
                if self._extender.callbacks.isInScope(request.getUrl()):
                    return True
                else:
                    return False
        else:
            return False



    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            if isRequest:
                self.currentrequest = self._extender.helpers.analyzeRequest(content)
                self.bodyoffset = self.currentrequest.getBodyOffset()
                self.currentreqstring = self._extender.helpers.bytesToString(content)
                self.bytebody = self.currentreqstring[self.bodyoffset:len(self.currentreqstring)]
                self.stringbody = self._extender.helpers.bytesToString(self.bytebody).decode("utf-8")
                self.encryptionfilepath = self._extender.encryptionfilepath
                self.decryptionpath = self._extender.decryptionfilepath
                
                
                self.mynewjson = OrderedDict()
                if str(self._extender.selectedrequesttpye) == "Whole Body (JSON)":
                    
                
                    decryptedvalue = Jsonvaluedecrypt(self.decryptionpath,self.stringbody)
                    
                    output = self._extender.helpers.stringToBytes(decryptedvalue)
                    
                    self._txtInput.setText(output)
                    self._txtInput.setEditable(True)
                    

                elif str(self._extender.selectedrequesttpye) == "JSON Value":
                    try:
                        json_object = json.loads(self.stringbody)
                        for key, value in json_object.items():
                            decryptedvalue = Jsonvaluedecrypt(self.decryptionpath,value)
                            self.mynewjson[key] = decryptedvalue
                        output = self._extender.helpers.stringToBytes(json.dumps(self.mynewjson)) 
                        self._txtInput.setText(output)
                        self._txtInput.setEditable(True)   
                    except ValueError:
                        self._txtInput.setText("Body is not in JSON, Kindly select the correct request type or verify the request")
                        self._txtInput.setEditable(False)    

                elif str(self._extender.selectedrequesttpye) == "JSON Key & Value":
                    try:
                        json_object = json.loads(self.stringbody)
                        for key, value in json_object.items():
                            decryptedkey = Jsonvaluedecrypt(self.decryptionpath,key)
                            decryptedvalue = Jsonvaluedecrypt(self.decryptionpath,value)
                            self.mynewjson[decryptedkey] = decryptedvalue
                        output = self._extender.helpers.stringToBytes(json.dumps(self.mynewjson)) 
                        self._txtInput.setText(output)
                        self._txtInput.setEditable(True)   
                    except ValueError:
                        self._txtInput.setText("Body is not in JSON, Kindly select the correct request type or verify the request")
                        self._txtInput.setEditable(False)

                elif str(self._extender.selectedrequesttpye) == "Custom Body":
                    decryptedvalue = Jsonvaluedecrypt(self.decryptionpath,self.stringbody)
                    output = self._extender.helpers.stringToBytes(decryptedvalue)
                    self._txtInput.setText(output)
                    self._txtInput.setEditable(True)

                elif str(self._extender.selectedrequesttpye) == "Custom Request":
                    self.header = self.currentrequest.getHeaders()
                    self._extender.callbacks.printOutput(str(self.header))
                    
                    output = Customrequestdecrypt(self.decryptionpath,str(self.header),self.stringbody)
                    self._txtInput.setText(self._extender.helpers.stringToBytes(output))
                    self._txtInput.setEditable(True)

                else:
                    self._txtInput.setText(None)
                    self._txtInput.setEditable(False)        

        
        self._currentMessage = content     



    def getMessage(self):

        # determine whether the user modified the  data
        if self._txtInput.isTextModified():
            # reserialize the data
            editabedbyte = self._txtInput.getText()
            self.editedstring = self._extender.helpers.bytesToString(editabedbyte)

            self.currentrequest = self._extender.helpers.analyzeRequest(self._currentMessage)
            self.bodyoffset = self.currentrequest.getBodyOffset()
            self.currentreqstring = self._extender.helpers.bytesToString(self.currentreqstring)
            self.bytebody = self.currentreqstring[self.bodyoffset:len(self.currentreqstring)]
            self.stringbody = self._extender.helpers.bytesToString(self.bytebody).decode("utf-8")
            self.encryptionfilepath = self._extender.encryptionfilepath
            self.decryptionpath = self._extender.decryptionfilepath
            self.header = self.currentrequest.getHeaders()
           


            self.mynewjson2 = OrderedDict()
            if str(self._extender.selectedrequesttpye) == "Whole Body (JSON)":
                    encrypted = Jsonvalueencrypt(self.encryptionfilepath,self.editedstring)
                    
                    output = self._extender.helpers.stringToBytes(encrypted)
                    return self._extender.helpers.buildHttpMessage(self.header,output)
                    #self._currentMessage = self._extender.helpers.buildHttpMessage(self.header,output)


            elif str(self._extender.selectedrequesttpye) == "JSON Value":

                try:

                    json_object = json.loads(self.editedstring)
                    for key, value in json_object.items():
                        encryptedvalue = Jsonvalueencrypt(self.encryptionfilepath,value)
                        self.mynewjson2[key] = encryptedvalue
                    output = self._extender.helpers.stringToBytes(json.dumps(self.mynewjson2)) 
                    return self._extender.helpers.buildHttpMessage(self.header,output)   
                except ValueError:
                    pass
                    #self._txtInput.setText("Body is not in JSON, Kindly select the correct request type or verify the request")
                    #self._txtInput.setEditable(False)

            elif str(self._extender.selectedrequesttpye) == "JSON Key & Value":
                try:
                    json_object = json.loads(self.editedstring)
                    for key, value in json_object.items():
                        encryptedkey = Jsonvalueencrypt(self.encryptionfilepath,key)
                        encryptedvalue = Jsonvalueencrypt(self.encryptionfilepath,value)
                        self.mynewjson[encryptedkey] = encryptedvalue
                    output = self._extender.helpers.stringToBytes(json.dumps(self.mynewjson)) 
                    return self._extender.helpers.buildHttpMessage(self.header,output)  
                except ValueError:
                    pass
                    #self._txtInput.setText("Body is not in JSON, Kindly select the correct request type or verify the request")
                    #self._txtInput.setEditable(False)


            elif str(self._extender.selectedrequesttpye) == "Custom Body":
                    encryptedvalue = Jsonvalueencrypt(self.encryptionfilepath,self.editedstring)
                    output = self._extender.helpers.stringToBytes(encryptedvalue)
                    return self._extender.helpers.buildHttpMessage(self.header,output)   

            
            elif str(self._extender.selectedrequesttpye) == "Custom Request":
                    
                    
                    output = Customrequestencrypt(self.encryptionfilepath,str(self.header),self.editedstring)
                    return self._extender.helpers.buildHttpMessage(self.header,output)  
                    
            
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()                