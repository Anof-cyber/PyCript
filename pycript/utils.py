from .decryption import Parameterdecrypt
from .encryption import Parameterencrypt
from java.util import ArrayList

## update json key and value both
def update_json_key_value(json_obj, selectedlang, decryptionpath,enc_dec):
    for key, value in json_obj.items():
        new_key = enc_dec(selectedlang, decryptionpath, key)
        if isinstance(value, dict):
            for inner_key, inner_value in value.items():
                new_inner_key = enc_dec(selectedlang, decryptionpath, inner_key)
                value[new_inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                if inner_key != new_inner_key:
                    del value[inner_key]
        elif isinstance(value, list):
            for i in range(len(value)):
                if isinstance(value[i], dict):
                    for inner_key, inner_value in value[i].items():
                        new_inner_key = enc_dec(selectedlang, decryptionpath, inner_key)
                        value[i][new_inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                        if inner_key != new_inner_key:
                            del value[i][inner_key]
                else:
                    value[i] = enc_dec(selectedlang, decryptionpath, value[i])
        else:
            json_obj[new_key] = enc_dec(selectedlang, decryptionpath, value)
            if key != new_key:
                del json_obj[key]
    return json_obj


# Update json body with decrypted json value (Burp default Parameter API doesn't work as expected for JSON)
def update_json_value(json_obj, selectedlang, decryptionpath,enc_dec):
    for key, value in json_obj.items():
        if isinstance(value, dict):
            for inner_key, inner_value in value.items():
                value[inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
        elif isinstance(value, list):
            for i in range(len(value)):
                if isinstance(value[i], dict):
                    for inner_key, inner_value in value[i].items():
                        value[i][inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                else:
                    value[i] = enc_dec(selectedlang, decryptionpath, value[i])
        else:
            json_obj[key] = enc_dec(selectedlang, decryptionpath, value)
    return json_obj



def process_custom_headers(updated_header):
    updatedheaders = list(updated_header.split("\n"))
    headerlist = ArrayList()
    for data in updatedheaders:
        headerlist.add(data.strip())
    return headerlist



def analyze_request(extender, items):
    req = extender.helpers.analyzeRequest(items)
    return req


# Return string format body and raw Headers from string request (It return raw headers not array/list format headers from burp header api)
# Used for  Custom request (Edit Header)
def extract_body_and_headers(request_inst, req):
    getody = req.getBodyOffset()
    body = request_inst[getody:]
    headers_str = request_inst[:getody].strip()
    return body, headers_str