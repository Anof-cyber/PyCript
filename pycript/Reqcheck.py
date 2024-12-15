

from .decryption import Parameterdecrypt
from .encryption import Parameterencrypt
from json import loads, dumps
from burp import IParameter
from .utils import update_json_value, update_json_key_value,process_custom_headers, extract_body_and_headers


def EncryptRequest(extender, currentreq,req):
    encryptionpath = extender.encryptionfilepath
    selectedlang = extender.languagepath.getText()
    selected_method = extender.reqmethodcombobox.getSelectedItem()
    parameters = req.getParameters()
    header = req.getHeaders()  # Get Array/last format header from burp header api (used for Custom Request)
    request_inst = extender.helpers.bytesToString(currentreq)    
    body, headers_str = extract_body_and_headers(request_inst, req)
    selected_request_inc_ex_ctype = extender.selected_request_inc_ex_ctype
    listofparam = extender.requestparamlist.getText().split(',')


    if str(extender.selectedrequesttpye) == "Complete Body":
        encryptedvalue, updated_header = Parameterencrypt(selectedlang, encryptionpath, body,headers_str)
        headerlist = process_custom_headers(updated_header)
        return extender.helpers.buildHttpMessage(headerlist, encryptedvalue)
        #output = extender.helpers.stringToBytes(encryptedvalue)
        #return extender.helpers.buildHttpMessage(header, output)

    elif str(extender.selectedrequesttpye) == "Parameter Value":
        return encrypt_and_update_parameters(extender, currentreq, encryptionpath, selected_method, selectedlang, body, parameters, header,selected_request_inc_ex_ctype,listofparam,headers_str)
    
    elif str(extender.selectedrequesttpye) == "Parameter Key and Value":
        return encrypt_and_update_parameter_keys_and_values(extender, currentreq, encryptionpath, selected_method, selectedlang, body, parameters, header,selected_request_inc_ex_ctype,listofparam,headers_str)
    


## Function to decrypt request when Burp Menu to decrypt request is triggered
def DecryptRequest(extender, currentreq,req):
    decryptionpath = extender.decryptionfilepath
    selectedlang = extender.languagepath.getText()
    selected_method = extender.reqmethodcombobox.getSelectedItem()
    selected_request_inc_ex_ctype = extender.selected_request_inc_ex_ctype
    listofparam = extender.requestparamlist.getText().split(',')
    

    parameters = req.getParameters()
    header = req.getHeaders()  # Get Array/last format header from burp header api (used for Custom Request)
    
    request_inst = extender.helpers.bytesToString(currentreq)
    
    body, headers_str = extract_body_and_headers(request_inst, req)
    
    if str(extender.selectedrequesttpye) == "Complete Body":
        decrypted_value, updated_header = Parameterdecrypt(selectedlang, decryptionpath, body,headers_str)
        headerlist = process_custom_headers(updated_header)
        return extender.helpers.buildHttpMessage(headerlist, decrypted_value)
        #output = extender.helpers.stringToBytes(decrypted_value)
        #return extender.helpers.buildHttpMessage(header, output)

    elif str(extender.selectedrequesttpye) == "Parameter Value":
        # Handle "Parameter Value" case
        return decrypt_and_update_parameters(extender, currentreq, decryptionpath, selected_method, selectedlang,body,parameters,header,selected_request_inc_ex_ctype,listofparam,headers_str)
    

    elif str(extender.selectedrequesttpye) == "Parameter Key and Value":
        return decrypt_and_update_parameter_keys_and_values(extender, currentreq, decryptionpath, selected_method, selectedlang, body, parameters, header,selected_request_inc_ex_ctype,listofparam,headers_str)
    




# Decrypt parameters
def decrypt_and_update_parameters(extender, currentreq, decryptionpath, selected_method, selectedlang, body, parameters,header,selected_request_inc_ex_ctype,listofparam,headers_str):
    
    # Go through all parameters
    for param in parameters:
        # Only decrypt GET parameters if  Selected method is GET
        if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
            decrypted_param, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
            currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypted_param, param.getType()))

        # If Selected Method is Body, exlcude GET parameter (Should exclude cookie param as well)
        elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
            # First Udpate the form body
            if param.getType() == IParameter.PARAM_BODY:
                    decrypted_param, _  =  Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypted_param, param.getType()))
            # If json then update json 
            elif param.getType() == IParameter.PARAM_JSON:
                json_object = loads(body)
                json_object = update_json_value(json_object, selectedlang, decryptionpath,Parameterdecrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
                output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
                currentreq = extender.helpers.buildHttpMessage(header, output)
                break

        # if BOTH is selected first update GET param values, then form body
        else:
            if param.getType() == IParameter.PARAM_URL:
                    decrypted_param, _  =  Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypted_param, param.getType()))

            elif param.getType() == IParameter.PARAM_BODY:
                decrypted_param, _  =  Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypted_param, param.getType()))

    # get the updated parameters from the update request
    parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
    header = extender.helpers.analyzeRequest(currentreq).getHeaders()

    for param in parameters:
        if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
                json_object = loads(body)
                json_object = update_json_value(json_object, selectedlang, decryptionpath,Parameterdecrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
                output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
                currentreq = extender.helpers.buildHttpMessage(header, output)
                break
    return currentreq

def decrypt_and_update_parameter_keys_and_values(extender, currentreq, decryptionpath, selected_method, selectedlang, body, parameters, header,selected_request_inc_ex_ctype,listofparam,headers_str):
    for param in parameters:
        if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
            decrypted_param_name, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getName(),headers_str)
            decrypted_param_value, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
            currentreq = extender.helpers.removeParameter(currentreq, param)
            new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
            currentreq = extender.helpers.addParameter(currentreq, new_param)

        elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
            if param.getType() == IParameter.PARAM_BODY:
                decrypted_param_name, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getName(),headers_str)
                decrypted_param_value, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)
            elif param.getType() == IParameter.PARAM_JSON:
                json_object = loads(body)
                json_object = update_json_key_value(json_object, selectedlang, decryptionpath,Parameterdecrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
                output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
                currentreq = extender.helpers.buildHttpMessage(header, output)
                break

        else:
            if param.getType() == IParameter.PARAM_URL:
                decrypted_param_name, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getName(),headers_str)
                decrypted_param_value, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)

            elif param.getType() == IParameter.PARAM_BODY:
                decrypted_param_name, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getName(),headers_str)
                decrypted_param_value, _ = Parameterdecrypt(selectedlang, decryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)

    parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
    header = extender.helpers.analyzeRequest(currentreq).getHeaders()

    for param in parameters:
        if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
            json_object = loads(body)
            json_object = update_json_key_value(json_object, selectedlang, decryptionpath,Parameterdecrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
            output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
            currentreq = extender.helpers.buildHttpMessage(header, output)
            break

    return currentreq


def encrypt_and_update_parameters(extender, currentreq, encryptionpath, selected_method, selectedlang, body, parameters, header,selected_request_inc_ex_ctype,listofparam,headers_str):
    for param in parameters:
        if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
            encrypted_param_value, _ = Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
            currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), encrypted_param_value, param.getType()))

        elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
            if param.getType() == IParameter.PARAM_BODY:
                encrypted_param_value, _ = Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), encrypted_param_value, param.getType()))
            elif param.getType() == IParameter.PARAM_JSON:
                json_object = loads(body)
                json_object = update_json_value(json_object, selectedlang, encryptionpath, Parameterencrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
                output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
                currentreq = extender.helpers.buildHttpMessage(header, output)
                break
        
        else:
            if param.getType() == IParameter.PARAM_URL:
                decrypteedparam, _ =  Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))

            elif param.getType() == IParameter.PARAM_BODY:
                decrypteedparam, _ =  Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))

    parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
    header = extender.helpers.analyzeRequest(currentreq).getHeaders()

    for param in parameters:
        if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
            json_object = loads(body)
            json_object = update_json_value(json_object, selectedlang, encryptionpath, Parameterencrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
            output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
            currentreq = extender.helpers.buildHttpMessage(header, output)
            break

    return currentreq

def encrypt_and_update_parameter_keys_and_values(extender, currentreq, encryptionpath, selected_method, selectedlang, body, parameters, header,selected_request_inc_ex_ctype,listofparam,headers_str):
    for param in parameters:
        if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
            encrypted_param_name, _ = Parameterencrypt(selectedlang, encryptionpath, param.getName(),headers_str)
            encrypted_param_value, _ = Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
            currentreq = extender.helpers.removeParameter(currentreq, param)
            new_param = extender.helpers.buildParameter(encrypted_param_name, encrypted_param_value, param.getType())
            currentreq = extender.helpers.addParameter(currentreq, new_param)

        elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
            if param.getType() == IParameter.PARAM_BODY:
                encrypted_param_name, _ = Parameterencrypt(selectedlang, encryptionpath, param.getName(),headers_str)
                encrypted_param_value, _ = Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(encrypted_param_name, encrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)

            elif param.getType() == IParameter.PARAM_JSON:
                json_object = loads(body)
                json_object = update_json_key_value(json_object, selectedlang, encryptionpath,Parameterencrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
                output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
                currentreq = extender.helpers.buildHttpMessage(header, output)
                break

        else:
            if param.getType() == IParameter.PARAM_URL:
                encrypted_param_name, _ = Parameterencrypt(selectedlang, encryptionpath, param.getName(),headers_str)
                encrypted_param_value, _ = Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(encrypted_param_name, encrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)

            elif param.getType() == IParameter.PARAM_BODY:
                encrypted_param_name, _ = Parameterencrypt(selectedlang, encryptionpath, param.getName(),headers_str)
                encrypted_param_value, _ = Parameterencrypt(selectedlang, encryptionpath, param.getValue(),headers_str)
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(encrypted_param_name, encrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)

    parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
    header = extender.helpers.analyzeRequest(currentreq).getHeaders()

    for param in parameters:
        if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
            json_object = loads(body)
            json_object = update_json_key_value(json_object, selectedlang, encryptionpath,Parameterencrypt,selected_request_inc_ex_ctype,listofparam,headers_str)
            output = extender.helpers.stringToBytes(dumps(json_object,separators=(',', ':')))
            currentreq = extender.helpers.buildHttpMessage(header, output)
            break

    return currentreq


