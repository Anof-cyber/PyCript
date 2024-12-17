from .decryption import Parameterdecrypt
from .encryption import Parameterencrypt

class StringCrypto:
    def __init__(self, extender, encpath, query, http_request_response):
        self._extender = extender
        self._selectedmessage = query
        self.message = http_request_response
        self.selectedlang = extender.languagepath.getText()
        self.encpath = encpath
        self.header = self.get_headers()
        self.headers_str = self.get_headers_str()

    def get_request_info(self):
        request = self.message.getRequest()
        return self._extender.helpers.analyzeRequest(request)

    def get_headers(self):
        request_info = self.get_request_info()
        return request_info.getHeaders()

    def get_headers_str(self):
        request_info = self.get_request_info()
        request_bytes = self.message.getRequest()
        request_str = self._extender.helpers.bytesToString(request_bytes)
        body_offset = request_info.getBodyOffset()
        headers_str = request_str[:body_offset].strip()
        return headers_str
    ### String Encryption Decryption Cannot Modify the header, Can read headers only for string from request
    def encrypt_string_request(self):
 

        encrypted, header = Parameterencrypt(self.selectedlang, self.encpath, self._selectedmessage,self.headers_str)
        return encrypted,header

    def decrypt_string_request(self):
        

        decrypted, header = Parameterdecrypt(self.selectedlang, self.encpath, self._selectedmessage,self.headers_str)
        return decrypted,header