from .decryption import Parameterdecrypt,Customrequestdecrypt
from .encryption import Parameterencrypt,Customrequestencrypt
from json import loads, dumps
from .utils import update_json_value, update_json_key_value


def encrypt_decrypt_response(extender,currentresp,response,enc_dec,enc_dec_type):
    selectedlang = extender.languagecombobox.getSelectedItem()
    if enc_dec_type== "Decrypt":
        enc_dec_file_path = extender.responsedecryptionfilepath
    else:
        enc_dec_file_path = extender.responseencryptionfilepath
    stringbody = get_response_body(extender,currentresp,response)
    header = response.getHeaders()
    selected_response_inc_ex_ctype = extender.selected_response_inc_ex_ctype
    listofparam = extender.responseparamlist1.getText().split(',')

    if str(extender.selectedresponsetpye) == "Complete Body":
        decryptedvalue = enc_dec(selectedlang, enc_dec_file_path, stringbody)
        output = extender.helpers.stringToBytes(decryptedvalue)
        return extender.helpers.buildHttpMessage(header, output)
    
    elif str(extender.selectedresponsetpye) == "JSON Value":
        json_object = loads(stringbody)
        json_object = update_json_value(json_object, selectedlang, enc_dec_file_path,enc_dec,selected_response_inc_ex_ctype,listofparam)
        output = extender.helpers.stringToBytes(dumps(json_object))
        return extender.helpers.buildHttpMessage(header, output)

    elif str(extender.selectedresponsetpye) == "JSON Key and Value":
        json_object = loads(stringbody)
        update_json_key_value(json_object, selectedlang, enc_dec_file_path,enc_dec,selected_response_inc_ex_ctype,listofparam)
        output = extender.helpers.stringToBytes(dumps(json_object))
        return extender.helpers.buildHttpMessage(header, output)




def get_response_body(extender,currentresp,response):
    bodyoffset = response.getBodyOffset()
    currentresponsestring = extender.helpers.bytesToString(currentresp)
    bytebody = currentresponsestring[bodyoffset:len(currentresponsestring)]
    stringbody = extender.helpers.bytesToString(bytebody).decode("utf-8")
    return stringbody

