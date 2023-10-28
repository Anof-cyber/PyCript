from .decryption import Parameterdecrypt, Customrequestdecrypt,Customeditrequestdecrypt
from .encryption import Parameterencrypt, Customrequestencrypt,Customeditrequestencrypt

class StringCrypto:
    def __init__(self, extender, encpath, query, http_request_response):
        self._extender = extender
        self._selectedmessage = query
        self.message = http_request_response
        self.selectedlang = extender.languagecombobox.getSelectedItem()
        self.encpath = encpath

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

    def encrypt_string(self):
        if self._extender.selectedrequst:
            self.header = self.get_headers()
            headers_str = self.get_headers_str()

        if self._extender.selectedrequesttpye == "Custom Request":
            encrypted = Customrequestencrypt(self.selectedlang, self.encpath, str(self.header), self._selectedmessage)
            return encrypted

        elif self._extender.selectedrequesttpye == "Custom Request (Edit Header)":
            encrypted = Customeditrequestencrypt(self.selectedlang, self.encpath, str(headers_str), self._selectedmessage)
            return encrypted

        else:
            encrypted = Parameterencrypt(self.selectedlang, self.encpath, self._selectedmessage)
            return encrypted

    def decrypt_string(self):
        if self._extender.selectedrequst:
            self.header = self.get_headers()
            headers_str = self.get_headers_str()

        if self._extender.selectedrequesttpye == "Custom Request":
            decrypted = Customrequestdecrypt(self.selectedlang, self.encpath, str(self.header), self._selectedmessage)
            return decrypted

        elif self._extender.selectedrequesttpye == "Custom Request (Edit Header)":
            decrypted = Customeditrequestdecrypt(self.selectedlang, self.encpath, str(headers_str), self._selectedmessage)
            return decrypted

        else:
            decrypted = Parameterdecrypt(self.selectedlang, self.encpath, self._selectedmessage)