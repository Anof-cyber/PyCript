from burp import IMessageEditorTab
import json
from .decryption import Jsonvaluedecrypt,Customrequestdecrypt
from .encryption import Jsonvalueencrypt,Customrequestencrypt
from collections import OrderedDict
from requestvalidator import decrypt,encrypt
from .Reqcheck import DecryptRequest

class CriptInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._txtInput = extender.callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self.controller = controller
        #self.selectedtab = self._extender.reqresponsecombobox.getSelectedItem()
        self.selectedtab = self._extender.reqresponsecombobox.getSelectedItem()
        extender.callbacks.customizeUiComponent(self._txtInput.getComponent())


    def getTabCaption(self):
        return "PyCript"   


    def getUiComponent(self):
        
        return self._txtInput.getComponent()


    def isEnabled(self, content, isRequest):
        
        if content and isRequest:
            if str(self._extender.selectedrequesttpye) == "None":
                return False

            elif str(self._extender.reqresponsecombobox.getSelectedItem()) == "Response":
                return False

            else:
                request = self._extender.helpers.analyzeRequest(self.controller.getHttpService(),self.controller.getRequest())
                if self._extender.callbacks.isInScope(request.getUrl()):
                    return True
                else:
                    return False

        



    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            if isRequest:



                output = decrypt(self._extender,content)
                self._txtInput.setText(output)
                self._txtInput.setEditable(True)


        self._currentMessage = content     



    def getMessage(self):

        # determine whether the user modified the  data
        if self._txtInput.isTextModified():
            # reserialize the data
            editabedbyte = self._txtInput.getText()
            output = encrypt(self._extender,editabedbyte)
            return output


        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()                