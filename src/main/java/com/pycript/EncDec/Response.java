package com.pycript.EncDec;

import org.apache.commons.lang3.tuple.Pair;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.pycript.ui.ConfigTab;
import com.pycript.utility.utils;

public class Response {

    public static HttpResponse encrypt(HttpResponse httpResponse, MontoyaApi api) {
        byte[] bodyBytes = httpResponse.body().getBytes();
        int bodyOffset = httpResponse.bodyOffset();
        String rawHeaders = (httpResponse.toString()).substring(0, bodyOffset).trim();

        if (ConfigTab.selectedResponseType.equals("Complete Body")) {
            Pair<byte[], String> result = Encryption.Parameterencrypt(
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedResponseEncryptionFile,
                bodyBytes,
                rawHeaders
            );
            return utils.buildHttpResponse(httpResponse, result.getLeft());
        }
        else if (ConfigTab.selectedResponseType.equals("Parameter Value")) {
            return utils.processJsonResponseBodyEncrypt(httpResponse, api,
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedResponseEncryptionFile,
                ConfigTab.getResponseParameterIncludeExcludeType(),
                ConfigTab.getResponseParameterList(),
                rawHeaders, false);
        }
        else if (ConfigTab.selectedResponseType.equals("Parameter Key and Value")) {
            return utils.processJsonResponseBodyEncrypt(httpResponse, api,
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedResponseEncryptionFile,
                ConfigTab.getResponseParameterIncludeExcludeType(),
                ConfigTab.getResponseParameterList(),
                rawHeaders, true);
        }

        return httpResponse;
    }

    public static HttpResponse decrypt(HttpResponse httpResponse, MontoyaApi api) {
        if (httpResponse == null) {
            return httpResponse;
        }

        byte[] bodyBytes = httpResponse.body().getBytes();
        int bodyOffset = httpResponse.bodyOffset();
        String rawHeaders = (httpResponse.toString()).substring(0, bodyOffset).trim();

        if (ConfigTab.selectedResponseType == null || ConfigTab.selectedResponseType.equals("None")) {
            return httpResponse;
        }

        if (ConfigTab.selectedResponseType.equals("Complete Body")) {
            Pair<byte[], String> result = Decryption.Parameterdecrypt(
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedResponseDecryptionFile,
                bodyBytes,
                rawHeaders
            );
            if (result != null && result.getLeft() != null) {
                return utils.buildHttpResponse(httpResponse, result.getLeft());
            }
        }
        else if (ConfigTab.selectedResponseType.equals("Parameter Value")) {
            return utils.processJsonResponseBody(httpResponse, api,
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedResponseDecryptionFile,
                ConfigTab.getResponseParameterIncludeExcludeType(),
                ConfigTab.getResponseParameterList(),
                rawHeaders, false);
        }
        else if (ConfigTab.selectedResponseType.equals("Parameter Key and Value")) {
            return utils.processJsonResponseBody(httpResponse, api,
                ConfigTab.languageTextField.getText(),
                ConfigTab.selectedResponseDecryptionFile,
                ConfigTab.getResponseParameterIncludeExcludeType(),
                ConfigTab.getResponseParameterList(),
                rawHeaders, true);
        }

        return httpResponse;
    }
}
