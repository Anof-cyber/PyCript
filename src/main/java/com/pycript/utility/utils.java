package com.pycript.utility;

import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.List;

public class utils {

    public static List<? extends HttpHeader> processCustomHeaders(String updatedHeader) {
        // Split the headers by newline
        String[] updatedHeaders = updatedHeader.split("\n");

        // Create a list to store the processed HttpHeader objects
        List<HttpHeader> headerList = new ArrayList<>();

        // Iterate through each header, trim it, and create an HttpHeader
        for (String data : updatedHeaders) {
            String trimmedHeader = data.trim();
            if (!trimmedHeader.isEmpty()) {
                headerList.add(HttpHeader.httpHeader(trimmedHeader));
            }
        }

        return headerList;
    }
}
