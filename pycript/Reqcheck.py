

from .decryption import Parameterdecrypt, Customrequestdecrypt,Customeditrequestdecrypt
from .encryption import Parameterencrypt, Customrequestencrypt,Customeditrequestencrypt
import json
from collections import OrderedDict
from burp import IParameter
from java.util import ArrayList
from base64 import b64encode












def DecryptRequest(extender,items):#, stringbody, header):

    
    decryptionpath = extender.decryptionfilepath
    req = extender.helpers.analyzeRequest(items)
    header = req.getHeaders()
    mynewjson = OrderedDict()
    gettingrequest = items.getRequest()
    selectedlang = extender.languagecombobox.getSelectedItem()
        
    requestinst = extender.helpers.bytesToString(gettingrequest)
    getody = req.getBodyOffset()
    body = requestinst[getody:len(requestinst)]
    headers_str = requestinst[:getody].strip()
    #headers_list = headers_str.splitlines()

    if str(extender.selectedrequesttpye) == "Complete Body":

        
        

        decryptedvalue = Parameterdecrypt(selectedlang, decryptionpath, body)
        output = extender.helpers.stringToBytes(decryptedvalue)
        return extender.helpers.buildHttpMessage(header, output)
    
    elif str(extender.selectedrequesttpye) == "Parameter Value":
        parameters = extender.helpers.analyzeRequest(items).getParameters()
        selected_method = extender.reqmethodcombobox.getSelectedItem()
        currentreq = items.getRequest()
        for param in parameters:
            if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
                decrypteedparam =  Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                
                currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))
            
            elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
                if param.getType() == IParameter.PARAM_BODY:
                    decrypteedparam =  Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))
                elif param.getType() == IParameter.PARAM_JSON:

                    json_object = json.loads(body)

                    for key, value in json_object.items():
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                value[inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        value[i][inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                                else:
                                    value[i] = Parameterdecrypt(selectedlang, decryptionpath, value[i])
                        else:
                            json_object[key] = Parameterdecrypt(selectedlang, decryptionpath, value)

                    output = extender.helpers.stringToBytes(json.dumps(json_object))
                    currentreq =  extender.helpers.buildHttpMessage(header, output)
                    break
                    
            else:

                if param.getType() == IParameter.PARAM_URL:
                    decrypteedparam =  Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))

                elif param.getType() == IParameter.PARAM_BODY:
                    decrypteedparam =  Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))

        parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
        header = extender.helpers.analyzeRequest(currentreq).getHeaders()
       
        for param in parameters:
            if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
                json_object = json.loads(body)

                for key, value in json_object.items():
                    if isinstance(value, dict):
                        for inner_key, inner_value in value.items():
                            value[inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                    elif isinstance(value, list):
                        for i in range(len(value)):
                            if isinstance(value[i], dict):
                                for inner_key, inner_value in value[i].items():
                                    value[i][inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                            else:
                                value[i] = Parameterdecrypt(selectedlang, decryptionpath, value[i])
                    else:
                        json_object[key] = Parameterdecrypt(selectedlang, decryptionpath, value)

                output = extender.helpers.stringToBytes(json.dumps(json_object))
                currentreq =  extender.helpers.buildHttpMessage(header, output)
                break
        return currentreq


    elif str(extender.selectedrequesttpye) == "Parameter Key and Value":
        parameters = extender.helpers.analyzeRequest(items).getParameters()
        selected_method = extender.reqmethodcombobox.getSelectedItem()
        currentreq = items.getRequest()
        for param in parameters:
            if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
                decrypted_param_name = Parameterdecrypt(selectedlang, decryptionpath, param.getName())
                decrypted_param_value = Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)


            elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
                if param.getType() == IParameter.PARAM_BODY:
                    decrypted_param_name = Parameterdecrypt(selectedlang, decryptionpath, param.getName())
                    decrypted_param_value = Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                    currentreq = extender.helpers.removeParameter(currentreq, param)
                    new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                    currentreq = extender.helpers.addParameter(currentreq, new_param)

                elif param.getType() == IParameter.PARAM_JSON:

                    json_object = json.loads(body)

                    for key, value in json_object.items():
                        new_key = Parameterdecrypt(selectedlang, decryptionpath, key)
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                new_inner_key = Parameterdecrypt(selectedlang, decryptionpath, inner_key)
                                value[new_inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[inner_key]
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        new_inner_key = Parameterdecrypt(selectedlang, decryptionpath, inner_key)
                                        value[i][new_inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                                        if inner_key != new_inner_key:
                                            del value[i][inner_key]
                                else:
                                    value[i] = Parameterdecrypt(selectedlang, decryptionpath, value[i])
                        else:
                            json_object[new_key] = Parameterdecrypt(selectedlang, decryptionpath, value)
                            if key != new_key:
                                del json_object[key]

                    output = extender.helpers.stringToBytes(json.dumps(json_object))
                    currentreq =  extender.helpers.buildHttpMessage(header, output)
                    break

            else:

                if param.getType() == IParameter.PARAM_URL:
                    decrypted_param_name = Parameterdecrypt(selectedlang, decryptionpath, param.getName())
                    decrypted_param_value = Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                    currentreq = extender.helpers.removeParameter(currentreq, param)
                    new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                    currentreq = extender.helpers.addParameter(currentreq, new_param)

                elif param.getType() == IParameter.PARAM_BODY:
                    decrypted_param_name = Parameterdecrypt(selectedlang, decryptionpath, param.getName())
                    decrypted_param_value = Parameterdecrypt(selectedlang, decryptionpath, param.getValue())
                    currentreq = extender.helpers.removeParameter(currentreq, param)
                    new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                    currentreq = extender.helpers.addParameter(currentreq, new_param)

        parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
        header = extender.helpers.analyzeRequest(currentreq).getHeaders()
       
        for param in parameters:
            if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
                json_object = json.loads(body)

                for key, value in json_object.items():
                        new_key = Parameterdecrypt(selectedlang, decryptionpath, key)
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                new_inner_key = Parameterdecrypt(selectedlang, decryptionpath, inner_key)
                                value[new_inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[inner_key]
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        new_inner_key = Parameterdecrypt(selectedlang, decryptionpath, inner_key)
                                        value[i][new_inner_key] = Parameterdecrypt(selectedlang, decryptionpath, inner_value)
                                        if inner_key != new_inner_key:
                                            del value[i][inner_key]
                                else:
                                    value[i] = Parameterdecrypt(selectedlang, decryptionpath, value[i])
                        else:
                            json_object[new_key] = Parameterdecrypt(selectedlang, decryptionpath, value)
                            if key != new_key:
                                del json_object[key]

                output = extender.helpers.stringToBytes(json.dumps(json_object))
                currentreq =  extender.helpers.buildHttpMessage(header, output)
                break

        return currentreq
    

    elif str(extender.selectedrequesttpye) == "Custom Request":

        extender.callbacks.printOutput(str(header))
        output = Customrequestdecrypt(selectedlang, decryptionpath, str(header), body)
        return extender.helpers.buildHttpMessage(header, output)
    
    elif str(extender.selectedrequesttpye) == "Custom Request (Edit Header)":
        currentreq = items.getRequest()        
        updatedheader, body = Customeditrequestdecrypt(selectedlang, decryptionpath, str(headers_str), body)
        
        updatedheaders = list(updatedheader.split("\n"))


        headerlist = ArrayList()
       
        for data in updatedheaders:
            headerlist.add(data.strip())
       
        return extender.helpers.buildHttpMessage(headerlist, body)



def EncryptRequest(extender,items):

    selectedlang = extender.languagecombobox.getSelectedItem()
    encryptionpath = extender.encryptionfilepath
    req = extender.helpers.analyzeRequest(items)
    header = req.getHeaders() 
    gettingrequest = items.getRequest()    
    requestinst = extender.helpers.bytesToString(gettingrequest)
    getody = req.getBodyOffset()
    body = requestinst[getody:len(requestinst)]
    headers_str = requestinst[:getody].strip()
    #headers_list = headers_str.splitlines()

    if str(extender.selectedrequesttpye) == "Complete Body":
        decryptedvalue = Parameterencrypt(selectedlang, encryptionpath, body)
        output = extender.helpers.stringToBytes(decryptedvalue)
        return extender.helpers.buildHttpMessage(header, output)
    


    elif str(extender.selectedrequesttpye) == "Parameter Value":
        parameters = extender.helpers.analyzeRequest(items).getParameters()
        selected_method = extender.reqmethodcombobox.getSelectedItem()
        currentreq = items.getRequest()
        for param in parameters:
            if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
                decrypteedparam =  Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                
                currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))
            
            elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
                if param.getType() == IParameter.PARAM_BODY:
                    decrypteedparam =  Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))
                elif param.getType() == IParameter.PARAM_JSON:

                    json_object = json.loads(body)

                    for key, value in json_object.items():
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                value[inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        value[i][inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                                else:
                                    value[i] = Parameterencrypt(selectedlang, encryptionpath, value[i])
                        else:
                            json_object[key] = Parameterencrypt(selectedlang, encryptionpath, value)

                    output = extender.helpers.stringToBytes(json.dumps(json_object))
                    currentreq =  extender.helpers.buildHttpMessage(header, output)
                    break
                    
            else:

                if param.getType() == IParameter.PARAM_URL:
                    decrypteedparam =  Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))

                elif param.getType() == IParameter.PARAM_BODY:
                    decrypteedparam =  Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                    currentreq = extender.helpers.updateParameter(currentreq, extender.helpers.buildParameter(param.getName(), decrypteedparam, param.getType()))

        parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
        header = extender.helpers.analyzeRequest(currentreq).getHeaders()
       
        for param in parameters:
            if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
                json_object = json.loads(body)

                for key, value in json_object.items():
                    if isinstance(value, dict):
                        for inner_key, inner_value in value.items():
                            value[inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                    elif isinstance(value, list):
                        for i in range(len(value)):
                            if isinstance(value[i], dict):
                                for inner_key, inner_value in value[i].items():
                                    value[i][inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                            else:
                                value[i] = Parameterencrypt(selectedlang, encryptionpath, value[i])
                    else:
                        json_object[key] = Parameterencrypt(selectedlang, encryptionpath, value)

                output = extender.helpers.stringToBytes(json.dumps(json_object))
                currentreq =  extender.helpers.buildHttpMessage(header, output)
                break
        return currentreq
    

    elif str(extender.selectedrequesttpye) == "Parameter Key and Value":
        parameters = extender.helpers.analyzeRequest(items).getParameters()
        selected_method = extender.reqmethodcombobox.getSelectedItem()
        currentreq = items.getRequest()
        for param in parameters:
            if selected_method == "GET" and param.getType() == IParameter.PARAM_URL:
                decrypted_param_name = Parameterencrypt(selectedlang, encryptionpath, param.getName())
                decrypted_param_value = Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                currentreq = extender.helpers.removeParameter(currentreq, param)
                new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                currentreq = extender.helpers.addParameter(currentreq, new_param)


            elif selected_method == "BODY" and param.getType() != IParameter.PARAM_URL:
                if param.getType() == IParameter.PARAM_BODY:
                    decrypted_param_name = Parameterencrypt(selectedlang, encryptionpath, param.getName())
                    decrypted_param_value = Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                    currentreq = extender.helpers.removeParameter(currentreq, param)
                    new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                    currentreq = extender.helpers.addParameter(currentreq, new_param)

                elif param.getType() == IParameter.PARAM_JSON:

                    json_object = json.loads(body)

                    for key, value in json_object.items():
                        new_key = Parameterencrypt(selectedlang, encryptionpath, key)
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                new_inner_key = Parameterencrypt(selectedlang, encryptionpath, inner_key)
                                value[new_inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[inner_key]
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        new_inner_key = Parameterencrypt(selectedlang, encryptionpath, inner_key)
                                        value[i][new_inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                                        if inner_key != new_inner_key:
                                            del value[i][inner_key]
                                else:
                                    value[i] = Parameterencrypt(selectedlang, encryptionpath, value[i])
                        else:
                            json_object[new_key] = Parameterencrypt(selectedlang, encryptionpath, value)
                            if key != new_key:
                                del json_object[key]

                    output = extender.helpers.stringToBytes(json.dumps(json_object))
                    currentreq =  extender.helpers.buildHttpMessage(header, output)
                    break

            else:

                if param.getType() == IParameter.PARAM_URL:
                    decrypted_param_name = Parameterencrypt(selectedlang, encryptionpath, param.getName())
                    decrypted_param_value = Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                    currentreq = extender.helpers.removeParameter(currentreq, param)
                    new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                    currentreq = extender.helpers.addParameter(currentreq, new_param)

                elif param.getType() == IParameter.PARAM_BODY:
                    decrypted_param_name = Parameterencrypt(selectedlang, encryptionpath, param.getName())
                    decrypted_param_value = Parameterencrypt(selectedlang, encryptionpath, param.getValue())
                    currentreq = extender.helpers.removeParameter(currentreq, param)
                    new_param = extender.helpers.buildParameter(decrypted_param_name, decrypted_param_value, param.getType())
                    currentreq = extender.helpers.addParameter(currentreq, new_param)

        parameters = extender.helpers.analyzeRequest(currentreq).getParameters()
        header = extender.helpers.analyzeRequest(currentreq).getHeaders()
       
        for param in parameters:
            if selected_method == "BOTH" and param.getType() == IParameter.PARAM_JSON:
                json_object = json.loads(body)

                for key, value in json_object.items():
                        new_key = Parameterencrypt(selectedlang, encryptionpath, key)
                        if isinstance(value, dict):
                            for inner_key, inner_value in value.items():
                                new_inner_key = Parameterencrypt(selectedlang, encryptionpath, inner_key)
                                value[new_inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                                if inner_key != new_inner_key:
                                    del value[inner_key]
                        elif isinstance(value, list):
                            for i in range(len(value)):
                                if isinstance(value[i], dict):
                                    for inner_key, inner_value in value[i].items():
                                        new_inner_key = Parameterencrypt(selectedlang, encryptionpath, inner_key)
                                        value[i][new_inner_key] = Parameterencrypt(selectedlang, encryptionpath, inner_value)
                                        if inner_key != new_inner_key:
                                            del value[i][inner_key]
                                else:
                                    value[i] = Parameterencrypt(selectedlang, encryptionpath, value[i])
                        else:
                            json_object[new_key] = Parameterencrypt(selectedlang, encryptionpath, value)
                            if key != new_key:
                                del json_object[key]

                output = extender.helpers.stringToBytes(json.dumps(json_object))
                currentreq =  extender.helpers.buildHttpMessage(header, output)
                break

        return currentreq
    
    elif str(extender.selectedrequesttpye) == "Custom Request":

        extender.callbacks.printOutput(str(header))
        output = Customrequestencrypt(selectedlang, encryptionpath, str(header), body)
        return extender.helpers.buildHttpMessage(header, output)
    

    elif str(extender.selectedrequesttpye) == "Custom Request (Edit Header)":
        currentreq = items.getRequest()        
        updatedheader, body = Customeditrequestencrypt(selectedlang, encryptionpath, str(headers_str), body)
        
        updatedheaders = list(updatedheader.split("\n"))
     
        headerlist = ArrayList()
       
        for data in updatedheaders:
            headerlist.add(data.strip())
       
        return extender.helpers.buildHttpMessage(headerlist, body)








