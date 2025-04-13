package com.pycript.EncDec;

import java.util.Base64;
import javax.servlet.http.HttpServletRequest;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

public class Request {

    private final MontoyaApi api;

    public static String encrypt(HttpRequest httpRequest, MontoyaApi api) {
        return "data";
    }

    public static String decrypt(HttpRequest httpRequest, MontoyaApi api) {
        return "data";
    }
}
