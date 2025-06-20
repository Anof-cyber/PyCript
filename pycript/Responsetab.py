from burp import IMessageEditorTab
from .decryption import Parameterdecrypt
from .encryption import Parameterencrypt
from .response_handler import encrypt_decrypt_response 
import json
from array import array

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
        if content is None or isRequest:
            return False

        if str(self._extender.selectedresponsetpye) == "None" or str(self._extender.reqresponsecombobox.getSelectedItem()) == "Request":
            return False

   

        return True


        
        

    # def setMessage(self, content, isRequest):
    #     if content is None:
    #         self._txtInput.setText(None)
    #         self._txtInput.setEditable(False)
        
    #     else:
    #         if not isRequest:

    #             if self.controller.getHttpService() is not None:
    #                 url = self._extender.helpers.analyzeRequest(self.controller.getHttpService(), self.controller.getRequest()).getUrl()
    #                 if self._extender.callbacks.isInScope(url):
    #                     self.currentresponse = self._extender.helpers.analyzeResponse(content)
    #                     output = encrypt_decrypt_response(self._extender,content,self.currentresponse,Parameterdecrypt,"Decrypt")
    #                     self._txtInput.setEditable(True)
                        
    #                 else:
    #                     output = "URL is not added in Scope"
    #                     self._txtInput.setEditable(False)
    #             else:
    #                 output = "HTTP Request Service Missing"
    #                 self._txtInput.setEditable(False)

                

    #             self._txtInput.setText(output)
                


    #     self._currentMessage = content
                
    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            if not isRequest:
                if self.controller.getHttpService() is not None:
                    url = self._extender.helpers.analyzeRequest(
                        self.controller.getHttpService(), self.controller.getRequest()
                    ).getUrl()

                    if self._extender.callbacks.isInScope(url):
                        response = self.controller.getResponse()
                        response_info = self._extender.helpers.analyzeResponse(response)

                        output = encrypt_decrypt_response(
                            self._extender, content, response_info, Parameterdecrypt, "Decrypt"
                        )

                        if output is None:
                            output = "Error: Decryption returned no data".encode('utf-8')
                        elif isinstance(output, array):
                            output = output.tostring()
                        elif isinstance(output, unicode):
                            output = output.encode('utf-8')

                        try:
                            response_info = self._extender.helpers.analyzeResponse(output)
                            body_offset = response_info.getBodyOffset()
                            full_str = self._extender.helpers.bytesToString(output)
                            body = full_str[body_offset:]
                            json_obj = json.loads(body.strip())
                            def decode_nested_json(obj):
                                if isinstance(obj, dict):
                                    return {
                                        k: decode_nested_json(json.loads(v)) if isinstance(v, basestring) and v.strip().startswith('{') else v
                                        for k, v in obj.items()
                                    }
                                elif isinstance(obj, list):
                                    return [decode_nested_json(item) for item in obj]
                                return obj

                            try:
                                json_obj = decode_nested_json(json_obj)
                            except Exception as e:
                                print("[PyCript DEBUG] Nested decoding failed:", str(e))

                            pretty = json.dumps(json_obj, indent=4)
                            pretty_bytes = pretty.replace('\n', '\r\n').encode('utf-8')



                            output = self._extender.helpers.buildHttpMessage(
                                response_info.getHeaders(),
                                pretty_bytes
                            )
                        except Exception as e:
                            print("[PyCript DEBUG] JSON response formatting failed:", str(e))

                    else:
                        output = "URL is not added in Scope".encode('utf-8')
                        self._txtInput.setEditable(False)

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