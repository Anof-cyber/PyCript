package com.pycript.EncDec;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolType;
import com.pycript.ui.ConfigTab;

import java.util.List;

public class AutoEncryptHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final List<ToolType> selectedToolTypes;

    public AutoEncryptHttpHandler(MontoyaApi api, List<ToolType> selectedToolTypes) {
        this.api = api;
        this.selectedToolTypes = selectedToolTypes;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            if (!selectedToolTypes.contains(requestToBeSent.toolSource().toolType())) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            if (!api.scope().isInScope(requestToBeSent.url())) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            if (ConfigTab.selectedRequestType == null || ConfigTab.selectedRequestType.equals("None")) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            if (ConfigTab.selectedRequestEncryptionFile == null || ConfigTab.selectedRequestEncryptionFile.isBlank() ||
                ConfigTab.selectedRequestDecryptionFile == null || ConfigTab.selectedRequestDecryptionFile.isBlank()) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            HttpRequest encryptedRequest = Request.encrypt(requestToBeSent, api);
            HttpRequest finalRequest = encryptedRequest.withService(requestToBeSent.httpService());

            return RequestToBeSentAction.continueWith(finalRequest);

        } catch (Exception e) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
