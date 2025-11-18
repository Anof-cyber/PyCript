package com.pycript.utility;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import org.apache.commons.lang3.tuple.Pair;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

public class utils {

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

    public static String updateRawValue(
            HttpParameter param,
            String selectedLang,
            String encryptionPath,
            BiFunction<String, String, Pair<byte[], String>> encDecFunction,
            String selectedRequestIncExcType,
            List<String> listOfParam,
            String headersStr) {

        String paramName = param.name();
        String paramValue = param.value();

        if (selectedRequestIncExcType == null) {
            Pair<byte[], String> result = encDecFunction.apply(selectedLang, encryptionPath);
            paramValue = new String(result.getLeft());
        } else if ("Include Parameters".equals(selectedRequestIncExcType) && listOfParam.contains(paramName)) {
            Pair<byte[], String> result = encDecFunction.apply(selectedLang, encryptionPath);
            paramValue = new String(result.getLeft());
        } else if ("Exclude Parameters".equals(selectedRequestIncExcType) && !listOfParam.contains(paramName)) {
            Pair<byte[], String> result = encDecFunction.apply(selectedLang, encryptionPath);
            paramValue = new String(result.getLeft());
        }

        return paramValue;
    }

    public static JsonElement updateJsonValue(
            JsonElement jsonElement,
            String selectedLang,
            String decryptionPath,
            BiFunction<byte[], String, Pair<byte[], String>> encDecFunction,
            String selectedRequestIncExcType,
            List<String> listOfParam,
            String headersStr) {

        if (selectedRequestIncExcType == null || "None".equals(selectedRequestIncExcType)) {
            return processAllJsonElements(jsonElement, selectedLang, decryptionPath, encDecFunction, headersStr);
        } else if ("Include Parameters".equals(selectedRequestIncExcType)) {
            return processJsonWithInclude(jsonElement, selectedLang, decryptionPath, encDecFunction, listOfParam, headersStr);
        } else if ("Exclude Parameters".equals(selectedRequestIncExcType)) {
            return processJsonWithExclude(jsonElement, selectedLang, decryptionPath, encDecFunction, listOfParam, headersStr);
        }

        return jsonElement;
    }

    private static JsonElement processAllJsonElements(
            JsonElement element,
            String selectedLang,
            String path,
            BiFunction<byte[], String, Pair<byte[], String>> encDecFunction,
            String headersStr) {

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            JsonObject newObj = new JsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                newObj.add(entry.getKey(), processAllJsonElements(entry.getValue(), selectedLang, path, encDecFunction, headersStr));
            }
            return newObj;
        } else if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            JsonArray newArr = new JsonArray();
            for (JsonElement item : arr) {
                newArr.add(processAllJsonElements(item, selectedLang, path, encDecFunction, headersStr));
            }
            return newArr;
        } else if (element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()) {
            String originalValue = element.getAsString();
            byte[] valueBytes = originalValue.getBytes();
            Pair<byte[], String> result = encDecFunction.apply(valueBytes, path);
            String decryptedValue = new String(result.getLeft());
            return new JsonPrimitive(decryptedValue);
        }

        return element;
    }

    private static JsonElement processJsonWithInclude(
            JsonElement element,
            String selectedLang,
            String path,
            BiFunction<byte[], String, Pair<byte[], String>> encDecFunction,
            List<String> listOfParam,
            String headersStr) {

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            JsonObject newObj = new JsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String key = entry.getKey();
                if (listOfParam.contains(key)) {
                    if (entry.getValue().isJsonPrimitive() && entry.getValue().getAsJsonPrimitive().isString()) {
                        String originalValue = entry.getValue().getAsString();
                        byte[] valueBytes = originalValue.getBytes();
                        Pair<byte[], String> result = encDecFunction.apply(valueBytes, path);
                        newObj.add(key, new JsonPrimitive(new String(result.getLeft())));
                    } else {
                        newObj.add(key, processJsonWithInclude(entry.getValue(), selectedLang, path, encDecFunction, listOfParam, headersStr));
                    }
                } else {
                    newObj.add(key, entry.getValue());
                }
            }
            return newObj;
        } else if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            JsonArray newArr = new JsonArray();
            for (JsonElement item : arr) {
                newArr.add(processJsonWithInclude(item, selectedLang, path, encDecFunction, listOfParam, headersStr));
            }
            return newArr;
        }

        return element;
    }

    private static JsonElement processJsonWithExclude(
            JsonElement element,
            String selectedLang,
            String path,
            BiFunction<byte[], String, Pair<byte[], String>> encDecFunction,
            List<String> listOfParam,
            String headersStr) {

        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            JsonObject newObj = new JsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String key = entry.getKey();
                if (!listOfParam.contains(key)) {
                    if (entry.getValue().isJsonPrimitive() && entry.getValue().getAsJsonPrimitive().isString()) {
                        String originalValue = entry.getValue().getAsString();
                        byte[] valueBytes = originalValue.getBytes();
                        Pair<byte[], String> result = encDecFunction.apply(valueBytes, path);
                        newObj.add(key, new JsonPrimitive(new String(result.getLeft())));
                    } else {
                        newObj.add(key, processJsonWithExclude(entry.getValue(), selectedLang, path, encDecFunction, listOfParam, headersStr));
                    }
                } else {
                    newObj.add(key, entry.getValue());
                }
            }
            return newObj;
        } else if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            JsonArray newArr = new JsonArray();
            for (JsonElement item : arr) {
                newArr.add(processJsonWithExclude(item, selectedLang, path, encDecFunction, listOfParam, headersStr));
            }
            return newArr;
        }

        return element;
    }
}