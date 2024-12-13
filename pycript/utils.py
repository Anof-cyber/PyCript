from .decryption import Parameterdecrypt
from .encryption import Parameterencrypt
from java.util import ArrayList

## update json key and value both
def update_json_key_value(json_obj, selectedlang, decryptionpath,enc_dec ,selected_request_response_inc_ex_ctype,listofparam):
    if selected_request_response_inc_ex_ctype is None:
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

    elif selected_request_response_inc_ex_ctype == "Include Parameters":
        for key, value in json_obj.items():
            if key in listofparam:
                new_key = enc_dec(selectedlang, decryptionpath, key)
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    if inner_key in listofparam:
                        new_inner_key = enc_dec(selectedlang, decryptionpath, inner_key)
                        value[new_inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                        if inner_key != new_inner_key:
                            del value[inner_key]
            elif isinstance(value, list):
                for i in range(len(value)):
                    if isinstance(value[i], dict):
                        for inner_key, inner_value in value[i].items():
                            if inner_key in listofparam:
                                new_inner_key = enc_dec(selectedlang, decryptionpath, inner_key)
                                value[i][new_inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[i][inner_key]
                    else:
                        if i in listofparam:
                            value[i] = enc_dec(selectedlang, decryptionpath, value[i])
            else:
                if key in listofparam:
                    json_obj[new_key] = enc_dec(selectedlang, decryptionpath, value)
                    if key != new_key:
                        del json_obj[key]

    elif selected_request_response_inc_ex_ctype == "Exclude Parameters":
        for key, value in json_obj.items():
            if key not in listofparam:
                new_key = enc_dec(selectedlang, decryptionpath, key)
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    if inner_key not in listofparam:
                        new_inner_key = enc_dec(selectedlang, decryptionpath, inner_key)
                        value[new_inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                        if inner_key != new_inner_key:
                            del value[inner_key]
            elif isinstance(value, list):
                for i in range(len(value)):
                    if isinstance(value[i], dict):
                        for inner_key, inner_value in value[i].items():
                            if inner_key not in listofparam:
                                new_inner_key = enc_dec(selectedlang, decryptionpath, inner_key)
                                value[i][new_inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[i][inner_key]
                    else:
                        if i not in listofparam:
                            value[i] = enc_dec(selectedlang, decryptionpath, value[i])
            else:
                if key not in listofparam:
                    json_obj[new_key] = enc_dec(selectedlang, decryptionpath, value)
                    if key != new_key:
                        del json_obj[key]

    return json_obj

def update_raw_value(parameter_value, selectedlang, encryptionpath, enc_dec, selected_request_response_inc_ex_ctype,listofparam):
    # Check if selectedreq_incexctype is None
    param_name = parameter_value.getName()
    param_value = parameter_value.getValue()
    
    if selected_request_response_inc_ex_ctype is None:
        # Process all parameters in the parameter_valueect
        new_value = enc_dec(selectedlang, encryptionpath, param_value)

    else:
        # Process parameters based on selectedparamtertype
        if selected_request_response_inc_ex_ctype == "Include Parameters":
            if isinstance(str(param_name), str):
                    if param_name in listofparam:
                            new_value = enc_dec(selectedlang, encryptionpath, param_value)
                    else:
                            new_value = param_value
            else:
                    if param_name in listofparam:
                        new_value = enc_dec(selectedlang, encryptionpath, param_value)         
               
        elif selected_request_response_inc_ex_ctype == "Exclude Parameters":
                if isinstance(str(param_name), str):
                    if param_name not in listofparam:
                            new_value = enc_dec(selectedlang, encryptionpath, param_value)
                    else:
                            new_value = param_value
                else:
                    if param_name not in listofparam:
                        new_value = enc_dec(selectedlang, encryptionpath, param_value)
    
    return new_value

def update_raw_key_value(param, selectedlang, encryptionpath, enc_dec ,selected_request_response_inc_ex_ctype,listofparam):
    if selected_request_response_inc_ex_ctype is None:
            new_param = param.getName()
            new_value = param.getValue()
            encrypted_param_name = enc_dec(selectedlang, encryptionpath, new_param)
            encrypted_param_value = enc_dec(selectedlang, encryptionpath, new_value)
           
    elif selected_request_response_inc_ex_ctype == "Include Parameters":
            if param.getName() in listofparam:
                new_param = param.getName()
                new_value = param.getValue()
                encrypted_param_name = enc_dec(selectedlang, encryptionpath, new_param)
                encrypted_param_value = enc_dec(selectedlang, encryptionpath, new_value)
            else:
                encrypted_param_name = param.getName()
                encrypted_param_value = param.getValue()

    elif selected_request_response_inc_ex_ctype == "Exclude Parameters":
            if param.getName() not in listofparam:
                new_param = param.getName()
                new_value = param.getValue()
                encrypted_param_name = enc_dec(selectedlang, encryptionpath, new_param)
                encrypted_param_value = enc_dec(selectedlang, encryptionpath, new_value)
            else:
                encrypted_param_name = param.getName()
                encrypted_param_value = param.getValue()
    else:
        encrypted_param_name = param.getName()
        encrypted_param_value = param.getValue()
    return encrypted_param_name, encrypted_param_value


def update_json_value(json_obj, selectedlang, decryptionpath, enc_dec, selected_request_response_inc_ex_ctype,listofparam):
    # Check if selectedreq_incexctype is None
    if selected_request_response_inc_ex_ctype is None:
        # Process all parameters in the JSON object
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
                value = enc_dec(selectedlang, decryptionpath, value)
                json_obj[key] = value

    else:
        # Process parameters based on selectedparamtertype
        if selected_request_response_inc_ex_ctype == "Include Parameters":
            for key, value in json_obj.items():
                if isinstance(value, dict):
                    for inner_key, inner_value in value.items():
                        if inner_key in listofparam:
                            value[inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                elif isinstance(value, list):
                    for i in range(len(value)):
                        if isinstance(value[i], dict):
                            for inner_key, inner_value in value[i].items():
                                if inner_key in listofparam:
                                    value[i][inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                        else:
                            if i in listofparam:
                                value[i] = enc_dec(selectedlang, decryptionpath, value[i])
                else:
                    if key in listofparam:
                        value = enc_dec(selectedlang, decryptionpath, value)
                        json_obj[key] = value
        elif selected_request_response_inc_ex_ctype == "Exclude Parameters":
            for key, value in json_obj.items():
                if isinstance(value, dict):
                    for inner_key, inner_value in value.items():
                        if inner_key not in listofparam:
                            value[inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                elif isinstance(value, list):
                    for i in range(len(value)):
                        if isinstance(value[i], dict):
                            for inner_key, inner_value in value[i].items():
                                if inner_key not in listofparam:
                                    value[i][inner_key] = enc_dec(selectedlang, decryptionpath, inner_value)
                        else:
                            if i not in listofparam:
                                value[i] = enc_dec(selectedlang, decryptionpath, value[i])
                else:
                    if key not in listofparam:
                        value = enc_dec(selectedlang, decryptionpath, value)
                        json_obj[key] = value
    return json_obj




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