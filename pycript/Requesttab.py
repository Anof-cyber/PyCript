from burp import IMessageEditorTab
from pycript.Reqcheck import DecryptRequest,EncryptRequest


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
        if isRequest:
            if content is None:
                return False

            if str(self._extender.selectedrequesttpye) == "None" or str(self._extender.reqresponsecombobox.getSelectedItem()) == "Response":
                return False

            return True
        return False 


    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            if isRequest:
                if self.controller.getHttpService() is not None:
               
                    url = self._extender.helpers.analyzeRequest(self.controller.getHttpService(), self.controller.getRequest()).getUrl()
                    if self._extender.callbacks.isInScope(url):
                        request = self._extender.helpers.analyzeRequest(content)
                        output = DecryptRequest(self._extender,content,request)
                    else:
                        output = "URL is not added in Scope"
                    self._txtInput.setText(output)
                    self._txtInput.setEditable(True)


        self._currentMessage = content     
        return 



    def getMessage(self):

        # determine whether the user modified the  data
        if self._txtInput.isTextModified():
            editabedbyte = self._txtInput.getText()
            req = self._extender.helpers.analyzeRequest(editabedbyte)
            output = EncryptRequest(self._extender,editabedbyte,req)
            return output


        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()                