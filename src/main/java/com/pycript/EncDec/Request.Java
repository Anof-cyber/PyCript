package com.pycript.EncDec;

import org.apache.commons.lang3.tuple.Pair;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.pycript.ui.ConfigTab;
import com.pycript.ui.LogTab;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.List;

public class Request {

    public static String encrypt(HttpRequest httpRequest, MontoyaApi api) {
        api.logging().logToOutput("Encrypting request...");
        return "data";
    }

    private static HttpRequest buildHttpRequest(String headers, byte[] body, MontoyaApi api) {
        String[] lines = headers.split("\r?\n");
        String[] requestLine = lines[0].split(" ", 3);
        String method = requestLine[0];
        String path = requestLine[1];

        HttpRequest newRequest = HttpRequest.httpRequest()
                .withMethod(method)
                .withPath(path);

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (!line.isEmpty()) {
                int colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    String headerName = line.substring(0, colonIndex).trim();
                    String headerValue = line.substring(colonIndex + 1).trim();
                    newRequest = newRequest.withHeader(HttpHeader.httpHeader(headerName, headerValue));
                }
            }
        }

        newRequest = newRequest.withBody(ByteArray.byteArray(body));
        return newRequest;
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

            byte[] decryptedBodyBytes = result.getLeft();
            String updatedHeader = result.getRight();

            HttpRequest updatedRequest = buildHttpRequest(updatedHeader, decryptedBodyBytes, api);
            return updatedRequest;
        } else if (ConfigTab.selectedRequestType.equals("Parameter Value")) {
            String selectedMethod = ConfigTab.requestmethodComboBox.getSelectedItem().toString();
            String selectedLang = ConfigTab.languageTextField.getText();
            String decryptionPath = ConfigTab.selectedRequestDecryptionFile;
            String selectedIncExcType = ConfigTab.getRequestParameterIncludeExcludeType();
            List<String> listOfParam = ConfigTab.getParameterList();

            return decryptAndUpdateParameters(httpRequest, api, bodyBytes, rawHeaders,
                selectedMethod, selectedLang, decryptionPath, selectedIncExcType, listOfParam);
        }

        return httpRequest;
    }

    private static HttpRequest decryptAndUpdateParameters(HttpRequest httpRequest, MontoyaApi api,
            byte[] bodyBytes, String rawHeaders, String selectedMethod, String selectedLang,
            String decryptionPath, String selectedIncExcType, List<String> listOfParam) {

        HttpRequest currentRequest = httpRequest;
        List<ParsedHttpParameter> parameters = currentRequest.parameters();

        for (ParsedHttpParameter param : parameters) {
            if (("GET".equals(selectedMethod) || "BOTH".equals(selectedMethod)) &&
                param.type() == HttpParameterType.URL) {

                String decryptedValue = processParameter(param, selectedLang, decryptionPath, selectedIncExcType, listOfParam, rawHeaders);
                currentRequest = currentRequest.withUpdatedParameters(
                    HttpParameter.urlParameter(param.name(), decryptedValue)
                );
            } else if (("BODY".equals(selectedMethod) || "BOTH".equals(selectedMethod)) &&
                       param.type() == HttpParameterType.BODY) {

                String decryptedValue = processParameter(param, selectedLang, decryptionPath, selectedIncExcType, listOfParam, rawHeaders);
                currentRequest = currentRequest.withUpdatedParameters(
                    HttpParameter.bodyParameter(param.name(), decryptedValue)
                );
            }
        }

        parameters = currentRequest.parameters();

        boolean hasJsonParams = false;
        for (ParsedHttpParameter param : parameters) {
            if (param.type() == HttpParameterType.JSON) {
                hasJsonParams = true;
                break;
            }
        }

        if (hasJsonParams && ("BODY".equals(selectedMethod) || "BOTH".equals(selectedMethod))) {
            String bodyString = currentRequest.bodyToString();

            Gson gson = new Gson();
            JsonElement jsonElement = gson.fromJson(bodyString, JsonElement.class);

            if (jsonElement.isJsonObject()) {
                JsonObject jsonObject = jsonElement.getAsJsonObject();
                JsonObject updatedObject = new JsonObject();

                for (String key : jsonObject.keySet()) {
                    JsonElement value = jsonObject.get(key);

                    if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                        String stringValue = value.getAsString();

                        boolean shouldDecrypt = false;

                        if (selectedIncExcType == null || "None".equals(selectedIncExcType)) {
                            shouldDecrypt = true;
                        } else if ("Include Parameters".equals(selectedIncExcType)) {
                            shouldDecrypt = listOfParam.contains(key);
                        } else if ("Exclude Parameters".equals(selectedIncExcType)) {
                            shouldDecrypt = !listOfParam.contains(key);
                        }

                        if (shouldDecrypt) {
                            byte[] valueBytes = stringValue.getBytes();
                            Pair<byte[], String> result = Decryption.Parameterdecrypt(selectedLang, decryptionPath, valueBytes, rawHeaders);
                            String decryptedValue = new String(result.getLeft());
                            updatedObject.addProperty(key, decryptedValue);
                        } else {
                            updatedObject.add(key, value);
                        }
                    } else {
                        updatedObject.add(key, value);
                    }
                }

                String updatedBody = gson.toJson(updatedObject);

                int bodyOffset = currentRequest.bodyOffset();
                String headers = (currentRequest.toString()).substring(0, bodyOffset).trim();

                currentRequest = buildHttpRequest(headers, updatedBody.getBytes(), api);
            }
        }

        return currentRequest;
    }

    private static String processParameter(ParsedHttpParameter param, String selectedLang,
                                          String decryptionPath, String selectedIncExcType,
                                          List<String> listOfParam, String rawHeaders) {
        String paramName = param.name();
        String paramValue = param.value();

        if (selectedIncExcType == null || selectedIncExcType.equals("None")) {
            Pair<byte[], String> result = Decryption.Parameterdecrypt(selectedLang, decryptionPath, paramValue.getBytes(), rawHeaders);
            return new String(result.getLeft());
        } else if ("Include Parameters".equals(selectedIncExcType) && listOfParam.contains(paramName)) {
            Pair<byte[], String> result = Decryption.Parameterdecrypt(selectedLang, decryptionPath, paramValue.getBytes(), rawHeaders);
            return new String(result.getLeft());
        } else if ("Exclude Parameters".equals(selectedIncExcType) && !listOfParam.contains(paramName)) {
            Pair<byte[], String> result = Decryption.Parameterdecrypt(selectedLang, decryptionPath, paramValue.getBytes(), rawHeaders);
            return new String(result.getLeft());
        }

        return paramValue;
    }
}
