from .decryption import Parameterdecrypt
from .encryption import Parameterencrypt
from java.util import ArrayList

## update json key and value both
def update_json_key_value(json_obj, selectedlang, decryptionpath,enc_dec ,selected_request_response_inc_ex_ctype,listofparam,headers_str=None):
    if selected_request_response_inc_ex_ctype is None:
        for key, value in json_obj.items():
            new_key , _ = enc_dec(selectedlang, decryptionpath, key,headers_str)
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    new_inner_key , _ = enc_dec(selectedlang, decryptionpath, inner_key,headers_str)
                    value[new_inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                    if inner_key != new_inner_key:
                        del value[inner_key]
            elif isinstance(value, list):
                for i in range(len(value)):
                    if isinstance(value[i], dict):
                        for inner_key, inner_value in value[i].items():
                            new_inner_key , _ = enc_dec(selectedlang, decryptionpath, inner_key,headers_str)
                            value[i][new_inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                            if inner_key != new_inner_key:
                                del value[i][inner_key]
                    else:
                        value[i] , _ = enc_dec(selectedlang, decryptionpath, value[i],headers_str)
            else:
                json_obj[new_key] , _ = enc_dec(selectedlang, decryptionpath, value,headers_str)
                if key != new_key:
                    del json_obj[key]

    elif selected_request_response_inc_ex_ctype == "Include Parameters":
        for key, value in json_obj.items():
            if key in listofparam:
                new_key , _ = enc_dec(selectedlang, decryptionpath, key,headers_str)
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    if inner_key in listofparam:
                        new_inner_key , _ = enc_dec(selectedlang, decryptionpath, inner_key,headers_str)
                        value[new_inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                        if inner_key != new_inner_key:
                            del value[inner_key]
            elif isinstance(value, list):
                for i in range(len(value)):
                    if isinstance(value[i], dict):
                        for inner_key, inner_value in value[i].items():
                            if inner_key in listofparam:
                                new_inner_key , _ = enc_dec(selectedlang, decryptionpath, inner_key,headers_str)
                                value[i][new_inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                                if inner_key != new_inner_key:
                                    del value[i][inner_key]
                    else:
                        if i in listofparam:
                            value[i] , _ = enc_dec(selectedlang, decryptionpath, value[i],headers_str)
            else:
                if key in listofparam:
                    json_obj[new_key] , _ = enc_dec(selectedlang, decryptionpath, value,headers_str)
                    if key != new_key:
                        del json_obj[key]

    elif selected_request_response_inc_ex_ctype == "Exclude Parameters":
        for key, value in json_obj.items():
            if key not in listofparam:
                new_key , _ = enc_dec(selectedlang, decryptionpath, key,headers_str)
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    if inner_key not in listofparam:
                        new_inner_key , _ = enc_dec(selectedlang, decryptionpath, inner_key,headers_str)
                        value[new_inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                        if inner_key != new_inner_key:
                            del value[inner_key]
            elif isinstance(value, list):
                for i in range(len(value)):
                    if isinstance(value[i], dict):
                        for inner_key, inner_value in value[i].items():
                            if inner_key not in listofparam:
                                new_inner_key , _ = enc_dec(selectedlang, decryptionpath, inner_key,headers_str)
                                value[i][new_inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                                if inner_key != new_inner_key:
                                    del value[i][inner_key]
                    else:
                        if i not in listofparam:
                            value[i] , _ = enc_dec(selectedlang, decryptionpath, value[i],headers_str)
            else:
                if key not in listofparam:
                    json_obj[new_key] , _ = enc_dec(selectedlang, decryptionpath, value,headers_str)
                    if key != new_key:
                        del json_obj[key]

    return json_obj

def update_json_value(json_obj, selectedlang, decryptionpath, enc_dec, selected_request_response_inc_ex_ctype,listofparam,headers_str=None):
    # Check if selectedreq_incexctype is None
    if selected_request_response_inc_ex_ctype is None:
        # Process all parameters in the JSON object
        for key, value in json_obj.items():
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    value[inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
            elif isinstance(value, list):
                for i in range(len(value)):
                    if isinstance(value[i], dict):
                        for inner_key, inner_value in value[i].items():
                            value[i][inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                    else:
                        value[i] , _ = enc_dec(selectedlang, decryptionpath, value[i],headers_str)
            else:
                value , _ = enc_dec(selectedlang, decryptionpath, value,headers_str)
                json_obj[key] = value

    else:
        # Process parameters based on selectedparamtertype
        if selected_request_response_inc_ex_ctype == "Include Parameters":
            for key, value in json_obj.items():
                if isinstance(value, dict):
                    for inner_key, inner_value in value.items():
                        if inner_key in listofparam:
                            value[inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                elif isinstance(value, list):
                    for i in range(len(value)):
                        if isinstance(value[i], dict):
                            for inner_key, inner_value in value[i].items():
                                if inner_key in listofparam:
                                    value[i][inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                        else:
                            if i in listofparam:
                                value[i] , _ = enc_dec(selectedlang, decryptionpath, value[i],headers_str)
                else:
                    if key in listofparam:
                        value , _ = enc_dec(selectedlang, decryptionpath, value,headers_str)
                        json_obj[key] = value
        elif selected_request_response_inc_ex_ctype == "Exclude Parameters":
            for key, value in json_obj.items():
                if isinstance(value, dict):
                    for inner_key, inner_value in value.items():
                        if inner_key not in listofparam:
                            value[inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                elif isinstance(value, list):
                    for i in range(len(value)):
                        if isinstance(value[i], dict):
                            for inner_key, inner_value in value[i].items():
                                if inner_key not in listofparam:
                                    value[i][inner_key] , _ = enc_dec(selectedlang, decryptionpath, inner_value,headers_str)
                        else:
                            if i not in listofparam:
                                value[i] , _ = enc_dec(selectedlang, decryptionpath, value[i],headers_str)
                else:
                    if key not in listofparam:
                        value , _ = enc_dec(selectedlang, decryptionpath, value,headers_str)
                        json_obj[key] = value
    return json_obj

def update_raw_value(param, selectedlang, encryptionpath, enc_dec, selected_request_response_inc_ex_ctype,listofparam,headers_str=None):
    param_name = param.getName()
    param_value = param.getValue()
     
    if selected_request_response_inc_ex_ctype is None:
        param_value , _ = enc_dec(selectedlang, encryptionpath, param_value,headers_str)

    elif selected_request_response_inc_ex_ctype == "Include Parameters" and param_name in listofparam:
            param_value , _ = enc_dec(selectedlang, encryptionpath, param_value,headers_str)
    
    elif selected_request_response_inc_ex_ctype == "Exclude Parameters" and param_name not in listofparam:
        param_value , _ = enc_dec(selectedlang, encryptionpath, param_value,headers_str)

    return param_value

    
def update_raw_key_value(param, selectedlang, encryptionpath, enc_dec ,selected_request_response_inc_ex_ctype,listofparam,headers_str=None):

    param_name = param.getName()
    param_value = param.getValue()
    if selected_request_response_inc_ex_ctype is None:
            param_name, _ = enc_dec(selectedlang, encryptionpath, param_name,headers_str)
            param_value, _ = enc_dec(selectedlang, encryptionpath, param_value,headers_str)
           
    elif selected_request_response_inc_ex_ctype == "Include Parameters" and param_name in listofparam:
            param_name , _ = enc_dec(selectedlang, encryptionpath, param_name,headers_str)
            param_value , _ = enc_dec(selectedlang, encryptionpath, param_value,headers_str)

    elif selected_request_response_inc_ex_ctype == "Exclude Parameters" and param_name not in listofparam:
        param_name , _ = enc_dec(selectedlang, encryptionpath, param_name,headers_str)
        param_value , _ = enc_dec(selectedlang, encryptionpath, param_value,headers_str)

    return param_name, param_value


def process_custom_headers(updated_header):
    updatedheaders = list(updated_header.split("\n"))
    headerlist = ArrayList()
    for data in updatedheaders:
        headerlist.add(data.strip())
    return headerlist



# Return string format body and raw Headers from string request (It return raw headers not array/list format headers from burp header api)
# Used for  Custom request (Edit Header)
def extract_body_and_headers(request_inst, req):
    getody = req.getBodyOffset()
    body = request_inst[getody:]
    headers_str = request_inst[:getody].strip()
    return body, headers_str

