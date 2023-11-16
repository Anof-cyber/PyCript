from burp import IMessageEditorTab
from .decryption import Parameterdecrypt,Customrequestdecrypt
from .encryption import Parameterencrypt,Customrequestencrypt
import json


class ResponeCriptInputTab(IMessageEditorTab):
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
        if content is not None and not isRequest:
            if str(self._extender.selectedresponsetpye) == "None":
                return False
            
            elif str(self._extender.reqresponsecombobox.getSelectedItem()) == "Request":
                return False

            else:
                request = self._extender.helpers.analyzeRequest(self.controller.getHttpService(),self.controller.getRequest())
                self.currentresponse = self._extender.helpers.analyzeResponse(self.controller.getResponse())
                self.statedminetype = self.currentresponse.getStatedMimeType()
                self.getInferredMimeType = self.currentresponse.getInferredMimeType()

                if self._extender.callbacks.isInScope(request.getUrl()):
                    #if self.statedminetype == "JSON" or self.getInferredMimeType == "JSON":
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
            if not isRequest:
                self.currentresponse = self._extender.helpers.analyzeResponse(content)
                self.selectedlang = self._extender.languagecombobox.getSelectedItem()
                self.decryptionresponsepath = self._extender.responsedecryptionfilepath



                self.bodyoffset = self.currentresponse.getBodyOffset()
                self.currentresponsestring = self._extender.helpers.bytesToString(content)
                self.bytebody = self.currentresponsestring[self.bodyoffset:len(self.currentresponsestring)]
                self.stringbody = self._extender.helpers.bytesToString(self.bytebody).decode("utf-8")


                if str(self._extender.selectedresponsetpye) == "Complete Body":

                    decryptedvalue = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, self.stringbody)
                    output = self._extender.helpers.stringToBytes(decryptedvalue)
                    self._txtInput.setText(output)
                    self._txtInput.setEditable(True)


                if str(self._extender.selectedresponsetpye) == "JSON Value":

                    json_object = json.loads(self.stringbody)
                    for key, value in json_object.items():
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                value[inner_key] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, inner_value)
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        value[i][inner_key] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, inner_value)
                                else:
                                    value[i] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, value[i])
                        else:
                            json_object[key] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, value)

                    output = self._extender.helpers.stringToBytes(json.dumps(json_object))
                    self._txtInput.setText(output)
                    self._txtInput.setEditable(True)
                
                if str(self._extender.selectedresponsetpye) == "JSON Key and Value":

                    json_object = json.loads(self.stringbody)

                    for key, value in json_object.items():
                        new_key = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, key)
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                new_inner_key = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, inner_key)
                                value[new_inner_key] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[inner_key]
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        new_inner_key = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, inner_key)
                                        value[i][new_inner_key] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, inner_value)
                                        if inner_key != new_inner_key:
                                            del value[i][inner_key]
                                else:
                                    value[i] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, value[i])
                        else:
                            json_object[new_key] = Parameterdecrypt(self.selectedlang, self.decryptionresponsepath, value)
                            if key != new_key:
                                del json_object[key]

                    output = self._extender.helpers.stringToBytes(json.dumps(json_object))
                    self._txtInput.setText(output)
                    self._txtInput.setEditable(True)


        self._currentMessage = content
                

    # check if response edited
    def getMessage(self):

        if self._txtInput.isTextModified():
            editabedbyte = self._txtInput.getText()
            self.editedstring = self._extender.helpers.bytesToString(editabedbyte)
            self.selectedlang = self._extender.languagecombobox.getSelectedItem()
            self.encryptionresponsepath = self._extender.responseencryptionfilepath

            self.currentresponse = self._extender.helpers.analyzeResponse(self._currentMessage)

            self.header = self.currentresponse.getHeaders()
            




            if str(self._extender.selectedresponsetpye) == "Complete Body":
                encrypted = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, self.editedstring)
                output = self._extender.helpers.stringToBytes(encrypted)
                return self._extender.helpers.buildHttpMessage(self.header,output)
            
            if str(self._extender.selectedresponsetpye) == "JSON Value":

                json_object = json.loads(self.editedstring)

                for key, value in json_object.items():
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                value[inner_key] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, inner_value)
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        value[i][inner_key] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, inner_value)
                                else:
                                    value[i] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, value[i])
                        else:
                            json_object[key] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, value)

                output = self._extender.helpers.stringToBytes(json.dumps(json_object))
                return self._extender.helpers.buildHttpMessage(self.header, output)
                

            if str(self._extender.selectedresponsetpye) == "JSON Key and Value":
                json_object = json.loads(self.editedstring)



                for key, value in json_object.items():
                        new_key = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, key)
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                new_inner_key = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, inner_key)
                                value[new_inner_key] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[inner_key]
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        new_inner_key = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, inner_key)
                                        value[i][new_inner_key] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, inner_value)
                                        if inner_key != new_inner_key:
                                            del value[i][inner_key]
                                else:
                                    value[i] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, value[i])
                        else:
                            json_object[new_key] = Parameterencrypt(self.selectedlang, self.encryptionresponsepath, value)
                            if key != new_key:
                                del json_object[key]

                output = self._extender.helpers.stringToBytes(json.dumps(json_object))
                return self._extender.helpers.buildHttpMessage(self.header, output)
        else:
            return self._currentMessage


    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()  