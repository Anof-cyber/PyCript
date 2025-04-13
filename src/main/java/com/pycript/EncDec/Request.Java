package com.pycript.encdec;

import java.util.Base64;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import com.pycript.ui.ConfigTab;
import com.pycript.encdec.Decryption;
import com.pycript.utility.utils;
public class Request {


    public static String encrypt(HttpRequest httpRequest, MontoyaApi api) {

        api.logging().logToOutput("Encrypting request...");
        return "data";
    }

    public static HttpRequest decrypt(HttpRequest httpRequest, MontoyaApi api) {
        //ConfigTab.selectedRequestType
        //ConfigTab.selectedRequestDecryptionFile
        //ConfigTab.reqresponsecombobox.getSelectedItem()
        //ConfigTab.requestmethodComboBox.getSelectedItem()
        //ConfigTab.languageTextField.getText();
        String string_body = httpRequest.bodyToString();
        int body_offset = httpRequest.bodyOffset();
        String raw_headers = (httpRequest.toString()).substring(0, body_offset).trim();


        if (ConfigTab.selectedRequestType.equals("Complete Body")) {

            Pair<String, String> result = Decryption.Parameterdecrypt(ConfigTab.languageTextField.getText(), ConfigTab.selectedRequestDecryptionFile, string_body, raw_headers);
            String decryptedValue = result.getLeft();  
            String updatedHeader = result.getRight();

            List<? extends HttpHeader> headerList = utils.processCustomHeaders(updatedHeader);

            // Create a new HttpRequest with the updated body
            HttpRequest updatedRequest = httpRequest.withBody(decryptedValue).withAddedHeaders(headerList);

            return updatedRequest;





         
        } 
        return httpRequest;
        
        
    }
}
