package com.pycript.utility;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.apache.commons.lang3.tuple.Pair;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import com.pycript.EncDec.Decryption;
import com.pycript.EncDec.Encryption;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class utils {

    public static boolean shouldDecryptParameter(String paramName, String selectedIncExcType, List<String> listOfParam) {
        if (selectedIncExcType == null || "None".equals(selectedIncExcType)) {
            return true;
        } else if ("Include Parameters".equals(selectedIncExcType)) {
            return listOfParam.contains(paramName);
        } else if ("Exclude Parameters".equals(selectedIncExcType)) {
            return !listOfParam.contains(paramName);
        }
        return false;
    }

    public static String decryptString(String input, String selectedLang, String decryptionPath, String rawHeaders) {
        Pair<byte[], String> result = Decryption.Parameterdecrypt(selectedLang, decryptionPath, input.getBytes(), rawHeaders);
        return new String(result.getLeft());
    }

    public static String encryptString(String input, String selectedLang, String encryptionPath, String rawHeaders) {
        Pair<byte[], String> result = Encryption.Parameterencrypt(selectedLang, encryptionPath, input.getBytes(), rawHeaders);
        return new String(result.getLeft());
    }

    public static boolean shouldProcessParameter(HttpParameterType paramType, String selectedMethod,
                                                   HttpParameterType targetType, String targetMethod) {
        return (targetMethod.equals(selectedMethod) || "BOTH".equals(selectedMethod)) && paramType == targetType;
    }

    public static HttpRequest buildHttpRequest(String headers, byte[] body, MontoyaApi api) {
        String[] lines = headers.split("\r?\n");
        String[] requestLine = lines[0].split(" ", 3);
        String method = requestLine[0];
        String path = requestLine[1];

        // Start with basic request with body
        HttpRequest newRequest = HttpRequest.httpRequest()
                .withMethod(method)
                .withPath(path)
                .withBody(ByteArray.byteArray(body));

        // Remove all existing headers first
        for (HttpHeader header : newRequest.headers()) {
            newRequest = newRequest.withRemovedHeader(header.name());
        }

        // Add all headers from the header string
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (!line.isEmpty()) {
                int colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    String headerName = line.substring(0, colonIndex).trim();
                    String headerValue = line.substring(colonIndex + 1).trim();
                    newRequest = newRequest.withAddedHeader(headerName, headerValue);
                }
            }
        }

        return newRequest;
    }

    public static HttpResponse buildHttpResponse(HttpResponse originalResponse, byte[] newBody) {
        // Use original response headers and just update the body
        return originalResponse.withBody(ByteArray.byteArray(newBody));
    }

    public static String processParameterValue(ParsedHttpParameter param, String selectedLang,
                                          String decryptionPath, String selectedIncExcType,
                                          List<String> listOfParam, String rawHeaders) {
        if (shouldDecryptParameter(param.name(), selectedIncExcType, listOfParam)) {
            return decryptString(param.value(), selectedLang, decryptionPath, rawHeaders);
        }
        return param.value();
    }

    public static String processParameterValueEncrypt(ParsedHttpParameter param, String selectedLang,
                                          String encryptionPath, String selectedIncExcType,
                                          List<String> listOfParam, String rawHeaders) {
        if (shouldDecryptParameter(param.name(), selectedIncExcType, listOfParam)) {
            return encryptString(param.value(), selectedLang, encryptionPath, rawHeaders);
        }
        return param.value();
    }

    public static Pair<String, String> processParameterKeyAndValue(ParsedHttpParameter param, String selectedLang,
                                          String decryptionPath, String selectedIncExcType,
                                          List<String> listOfParam, String rawHeaders) {
        if (shouldDecryptParameter(param.name(), selectedIncExcType, listOfParam)) {
            String decryptedName = decryptString(param.name(), selectedLang, decryptionPath, rawHeaders);
            String decryptedValue = decryptString(param.value(), selectedLang, decryptionPath, rawHeaders);
            return org.apache.commons.lang3.tuple.ImmutablePair.of(decryptedName, decryptedValue);
        }
        return org.apache.commons.lang3.tuple.ImmutablePair.of(param.name(), param.value());
    }

    public static Pair<String, String> processParameterKeyAndValueEncrypt(ParsedHttpParameter param, String selectedLang,
                                          String encryptionPath, String selectedIncExcType,
                                          List<String> listOfParam, String rawHeaders) {
        if (shouldDecryptParameter(param.name(), selectedIncExcType, listOfParam)) {
            String encryptedName = encryptString(param.name(), selectedLang, encryptionPath, rawHeaders);
            String encryptedValue = encryptString(param.value(), selectedLang, encryptionPath, rawHeaders);
            return org.apache.commons.lang3.tuple.ImmutablePair.of(encryptedName, encryptedValue);
        }
        return org.apache.commons.lang3.tuple.ImmutablePair.of(param.name(), param.value());
    }

    public static HttpRequest updateParameter(HttpRequest request, ParsedHttpParameter param,
                                               String selectedLang, String decryptionPath, String selectedIncExcType,
                                               List<String> listOfParam, String rawHeaders, boolean decryptKeys,
                                               HttpParameterType paramType) {
        if (decryptKeys) {
            Pair<String, String> decrypted = processParameterKeyAndValue(param, selectedLang, decryptionPath,
                selectedIncExcType, listOfParam, rawHeaders);
            request = request.withRemovedParameters(param);
            HttpParameter newParam = paramType == HttpParameterType.URL
                ? HttpParameter.urlParameter(decrypted.getLeft(), decrypted.getRight())
                : HttpParameter.bodyParameter(decrypted.getLeft(), decrypted.getRight());
            return request.withAddedParameters(newParam);
        } else {
            String decryptedValue = processParameterValue(param, selectedLang, decryptionPath,
                selectedIncExcType, listOfParam, rawHeaders);
            HttpParameter newParam = paramType == HttpParameterType.URL
                ? HttpParameter.urlParameter(param.name(), decryptedValue)
                : HttpParameter.bodyParameter(param.name(), decryptedValue);
            return request.withUpdatedParameters(newParam);
        }
    }

    public static HttpRequest updateParameterEncrypt(HttpRequest request, ParsedHttpParameter param,
                                               String selectedLang, String encryptionPath, String selectedIncExcType,
                                               List<String> listOfParam, String rawHeaders, boolean encryptKeys,
                                               HttpParameterType paramType) {
        if (encryptKeys) {
            Pair<String, String> encrypted = processParameterKeyAndValueEncrypt(param, selectedLang, encryptionPath,
                selectedIncExcType, listOfParam, rawHeaders);
            request = request.withRemovedParameters(param);
            HttpParameter newParam = paramType == HttpParameterType.URL
                ? HttpParameter.urlParameter(encrypted.getLeft(), encrypted.getRight())
                : HttpParameter.bodyParameter(encrypted.getLeft(), encrypted.getRight());
            return request.withAddedParameters(newParam);
        } else {
            String encryptedValue = processParameterValueEncrypt(param, selectedLang, encryptionPath,
                selectedIncExcType, listOfParam, rawHeaders);
            HttpParameter newParam = paramType == HttpParameterType.URL
                ? HttpParameter.urlParameter(param.name(), encryptedValue)
                : HttpParameter.bodyParameter(param.name(), encryptedValue);
            return request.withUpdatedParameters(newParam);
        }
    }

    public static boolean hasJsonParameters(HttpRequest request) {
        for (ParsedHttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.JSON) {
                return true;
            }
        }
        return false;
    }

    public static HttpRequest processJsonBody(HttpRequest currentRequest, MontoyaApi api, String selectedLang,
                                               String decryptionPath, String selectedIncExcType,
                                               List<String> listOfParam, String rawHeaders, boolean decryptKeys) {
        String bodyString = currentRequest.bodyToString();
        Gson gson = new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
        JsonElement jsonElement = gson.fromJson(bodyString, JsonElement.class);

        if (jsonElement.isJsonObject()) {
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonObject updatedObject = new JsonObject();

            for (String key : jsonObject.keySet()) {
                JsonElement value = jsonObject.get(key);

                if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                    String stringValue = value.getAsString();

                    if (shouldDecryptParameter(key, selectedIncExcType, listOfParam)) {
                        if (decryptKeys) {
                            String decryptedKey = decryptString(key, selectedLang, decryptionPath, rawHeaders);
                            String decryptedValue = decryptString(stringValue, selectedLang, decryptionPath, rawHeaders);
                            updatedObject.addProperty(decryptedKey, decryptedValue);
                        } else {
                            String decryptedValue = decryptString(stringValue, selectedLang, decryptionPath, rawHeaders);
                            updatedObject.addProperty(key, decryptedValue);
                        }
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
            return buildHttpRequest(headers, updatedBody.getBytes(), api);
        }

        return currentRequest;
    }

    public static HttpRequest processJsonBodyEncrypt(HttpRequest currentRequest, MontoyaApi api, String selectedLang,
                                               String encryptionPath, String selectedIncExcType,
                                               List<String> listOfParam, String rawHeaders, boolean encryptKeys) {
        String bodyString = currentRequest.bodyToString();
        Gson gson = new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
        JsonElement jsonElement = gson.fromJson(bodyString, JsonElement.class);

        if (jsonElement.isJsonObject()) {
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonObject updatedObject = new JsonObject();

            for (String key : jsonObject.keySet()) {
                JsonElement value = jsonObject.get(key);

                if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                    String stringValue = value.getAsString();

                    if (shouldDecryptParameter(key, selectedIncExcType, listOfParam)) {
                        if (encryptKeys) {
                            String encryptedKey = encryptString(key, selectedLang, encryptionPath, rawHeaders);
                            String encryptedValue = encryptString(stringValue, selectedLang, encryptionPath, rawHeaders);
                            updatedObject.addProperty(encryptedKey, encryptedValue);
                        } else {
                            String encryptedValue = encryptString(stringValue, selectedLang, encryptionPath, rawHeaders);
                            updatedObject.addProperty(key, encryptedValue);
                        }
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
            return buildHttpRequest(headers, updatedBody.getBytes(), api);
        }

        return currentRequest;
    }

    public static HttpResponse processJsonResponseBody(HttpResponse currentResponse, MontoyaApi api, String selectedLang,
                                               String decryptionPath, String selectedIncExcType,
                                               List<String> listOfParam, String rawHeaders, boolean decryptKeys) {
        String bodyString = currentResponse.bodyToString();
        Gson gson = new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
        JsonElement jsonElement = gson.fromJson(bodyString, JsonElement.class);

        if (jsonElement.isJsonObject()) {
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonObject updatedObject = new JsonObject();

            for (String key : jsonObject.keySet()) {
                JsonElement value = jsonObject.get(key);

                if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                    String stringValue = value.getAsString();

                    if (shouldDecryptParameter(key, selectedIncExcType, listOfParam)) {
                        if (decryptKeys) {
                            String decryptedKey = decryptString(key, selectedLang, decryptionPath, rawHeaders);
                            String decryptedValue = decryptString(stringValue, selectedLang, decryptionPath, rawHeaders);
                            updatedObject.addProperty(decryptedKey, decryptedValue);
                        } else {
                            String decryptedValue = decryptString(stringValue, selectedLang, decryptionPath, rawHeaders);
                            updatedObject.addProperty(key, decryptedValue);
                        }
                    } else {
                        updatedObject.add(key, value);
                    }
                } else {
                    updatedObject.add(key, value);
                }
            }

            String updatedBody = gson.toJson(updatedObject);
            return buildHttpResponse(currentResponse, updatedBody.getBytes());
        }

        return currentResponse;
    }

    public static HttpResponse processJsonResponseBodyEncrypt(HttpResponse currentResponse, MontoyaApi api, String selectedLang,
                                               String encryptionPath, String selectedIncExcType,
                                               List<String> listOfParam, String rawHeaders, boolean encryptKeys) {
        String bodyString = currentResponse.bodyToString();
        Gson gson = new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
        JsonElement jsonElement = gson.fromJson(bodyString, JsonElement.class);

        if (jsonElement.isJsonObject()) {
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonObject updatedObject = new JsonObject();

            for (String key : jsonObject.keySet()) {
                JsonElement value = jsonObject.get(key);

                if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                    String stringValue = value.getAsString();

                    if (shouldDecryptParameter(key, selectedIncExcType, listOfParam)) {
                        if (encryptKeys) {
                            String encryptedKey = encryptString(key, selectedLang, encryptionPath, rawHeaders);
                            String encryptedValue = encryptString(stringValue, selectedLang, encryptionPath, rawHeaders);
                            updatedObject.addProperty(encryptedKey, encryptedValue);
                        } else {
                            String encryptedValue = encryptString(stringValue, selectedLang, encryptionPath, rawHeaders);
                            updatedObject.addProperty(key, encryptedValue);
                        }
                    } else {
                        updatedObject.add(key, value);
                    }
                } else {
                    updatedObject.add(key, value);
                }
            }

            String updatedBody = gson.toJson(updatedObject);
            return buildHttpResponse(currentResponse, updatedBody.getBytes());
        }

        return currentResponse;
    }

    public static List<? extends HttpHeader> processCustomHeaders(String updatedHeader) {
        String[] updatedHeaders = updatedHeader.split("\n");
        List<HttpHeader> headerList = new ArrayList<>();

        for (String data : updatedHeaders) {
            String trimmedHeader = data.trim();
            if (!trimmedHeader.isEmpty()) {
                headerList.add(HttpHeader.httpHeader(trimmedHeader));
            }
        }

        return headerList;
    }
}