from burp import IMessageEditorTab
from .decryption import Parameterdecrypt
from .encryption import Parameterencrypt
from .response_handler import encrypt_decrypt_response 


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
                    if self.statedminetype == "JSON" or self.getInferredMimeType == "JSON":
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

                output = encrypt_decrypt_response(self._extender,content,self.currentresponse,Parameterdecrypt,"Decrypt")
                

                self._txtInput.setText(output)
                self._txtInput.setEditable(True)


        self._currentMessage = content
                

    # check if response edited
    def getMessage(self):

        if self._txtInput.isTextModified():
            editabedbyte = self._txtInput.getText()
            self.currentresponse = self._extender.helpers.analyzeResponse(editabedbyte)
            return  encrypt_decrypt_response(self._extender,editabedbyte,self.currentresponse,Parameterencrypt,"Encrypt")
        else:
            return self._currentMessage


    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()  