package com.pycript.EncDec;

import org.apache.commons.lang3.tuple.Pair;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.pycript.ui.ConfigTab;
import com.pycript.utility.utils;

import java.util.List;

public class Request {

    public static HttpRequest encrypt(HttpRequest httpRequest, MontoyaApi api) {
        byte[] bodyBytes = httpRequest.body().getBytes();
        int bodyOffset = httpRequest.bodyOffset();
        String rawHeaders = (httpRequest.toString()).substring(0, bodyOffset).trim();

        if (ConfigTab.selectedRequestType.equals("Complete Body")) {
            Pair<byte[], String> result = Encryption.Parameterencrypt(
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedRequestEncryptionFile,
                bodyBytes,
                rawHeaders
            );
            return utils.buildHttpRequest(result.getRight(), result.getLeft(), api);
        }
        else if (ConfigTab.selectedRequestType.equals("Parameter Value") ||
                   ConfigTab.selectedRequestType.equals("Parameter Key and Value")) {

            boolean encryptKeys = ConfigTab.selectedRequestType.equals("Parameter Key and Value");
            return encryptAndUpdateParameters(httpRequest, api, rawHeaders,
                ConfigTab.requestmethodComboBox.getSelectedItem().toString(),
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedRequestEncryptionFile,
                ConfigTab.getRequestParameterIncludeExcludeType(),
                ConfigTab.getParameterList(),
                encryptKeys);
        }

        return httpRequest;
    }

    public static HttpRequest decrypt(HttpRequest httpRequest, MontoyaApi api) {
        byte[] bodyBytes = httpRequest.body().getBytes();
        int bodyOffset = httpRequest.bodyOffset();
        String rawHeaders = (httpRequest.toString()).substring(0, bodyOffset).trim();

        if (ConfigTab.selectedRequestType.equals("Complete Body")) {
            Pair<byte[], String> result = Decryption.Parameterdecrypt(
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedRequestDecryptionFile,
                bodyBytes,
                rawHeaders
            );
            return utils.buildHttpRequest(result.getRight(), result.getLeft(), api);
        }
        else if (ConfigTab.selectedRequestType.equals("Parameter Value") ||
                   ConfigTab.selectedRequestType.equals("Parameter Key and Value")) {

            boolean decryptKeys = ConfigTab.selectedRequestType.equals("Parameter Key and Value");
            return decryptAndUpdateParameters(httpRequest, api, rawHeaders,
                ConfigTab.requestmethodComboBox.getSelectedItem().toString(),
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedRequestDecryptionFile,
                ConfigTab.getRequestParameterIncludeExcludeType(),
                ConfigTab.getParameterList(),
                decryptKeys);
        }

        return httpRequest;
    }

    private static HttpRequest decryptAndUpdateParameters(HttpRequest httpRequest, MontoyaApi api,
            String rawHeaders, String selectedMethod, String selectedLang,
            String decryptionPath, String selectedIncExcType, List<String> listOfParam, boolean decryptKeys) {

        HttpRequest currentRequest = httpRequest;
        List<ParsedHttpParameter> parameters = currentRequest.parameters();

        for (ParsedHttpParameter param : parameters) {
            if (utils.shouldProcessParameter(param.type(), selectedMethod, HttpParameterType.URL, "GET")) {
                currentRequest = utils.updateParameter(currentRequest, param, selectedLang, decryptionPath,
                    selectedIncExcType, listOfParam, rawHeaders, decryptKeys, HttpParameterType.URL);
            } else if (utils.shouldProcessParameter(param.type(), selectedMethod, HttpParameterType.BODY, "BODY")) {
                currentRequest = utils.updateParameter(currentRequest, param, selectedLang, decryptionPath,
                    selectedIncExcType, listOfParam, rawHeaders, decryptKeys, HttpParameterType.BODY);
            }
        }

        if (utils.hasJsonParameters(currentRequest) && ("BODY".equals(selectedMethod) || "BOTH".equals(selectedMethod))) {
            currentRequest = utils.processJsonBody(currentRequest, api, selectedLang, decryptionPath,
                selectedIncExcType, listOfParam, rawHeaders, decryptKeys);
        }

        return currentRequest;
    }

    private static HttpRequest encryptAndUpdateParameters(HttpRequest httpRequest, MontoyaApi api,
            String rawHeaders, String selectedMethod, String selectedLang,
            String encryptionPath, String selectedIncExcType, List<String> listOfParam, boolean encryptKeys) {

        HttpRequest currentRequest = httpRequest;
        List<ParsedHttpParameter> parameters = currentRequest.parameters();

        for (ParsedHttpParameter param : parameters) {
            if (utils.shouldProcessParameter(param.type(), selectedMethod, HttpParameterType.URL, "GET")) {
                currentRequest = utils.updateParameterEncrypt(currentRequest, param, selectedLang, encryptionPath,
                    selectedIncExcType, listOfParam, rawHeaders, encryptKeys, HttpParameterType.URL);
            } else if (utils.shouldProcessParameter(param.type(), selectedMethod, HttpParameterType.BODY, "BODY")) {
                currentRequest = utils.updateParameterEncrypt(currentRequest, param, selectedLang, encryptionPath,
                    selectedIncExcType, listOfParam, rawHeaders, encryptKeys, HttpParameterType.BODY);
            }
        }

        if (utils.hasJsonParameters(currentRequest) && ("BODY".equals(selectedMethod) || "BOTH".equals(selectedMethod))) {
            currentRequest = utils.processJsonBodyEncrypt(currentRequest, api, selectedLang, encryptionPath,
                selectedIncExcType, listOfParam, rawHeaders, encryptKeys);
        }

        return currentRequest;
    }
}
