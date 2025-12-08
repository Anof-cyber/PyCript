package com.pycript;

import java.awt.Component;
import com.pycript.ui.ConfigTab;
import com.pycript.EncDec.Response;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;

class ResponseHttpResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private final MontoyaApi api;
    private final RawEditor responseEditor;
    private HttpRequestResponse requestResponse;

    ResponseHttpResponseEditor(MontoyaApi api, EditorCreationContext creationContext) {
        this.api = api;
        responseEditor = api.userInterface().createRawEditor();
    }

    @Override
    public HttpResponse getResponse() {
        HttpResponse response;

        if (responseEditor.isModified()) {
            ByteArray modifiedContent = responseEditor.getContents();
            HttpResponse modifiedResponse = HttpResponse.httpResponse(modifiedContent);
            response = Response.encrypt(modifiedResponse, api);
        } else {
            response = requestResponse.response();
        }

        return response;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;

        if (requestResponse == null) {
            this.responseEditor.setEditable(false);
            return;
        }

        if (requestResponse.response() == null || requestResponse.response().toByteArray().length() == 0) {
            this.responseEditor.setEditable(false);
            return;
        }

        HttpResponse response = requestResponse.response();

        if (requestResponse.request() == null || !api.scope().isInScope(requestResponse.request().url())) {
            this.responseEditor.setEditable(false);
            this.responseEditor.setContents(ByteArray.byteArray(api.utilities().byteUtils().convertFromString("Request is out of scope")));
        } else {
            this.responseEditor.setEditable(true);
            try {
                HttpResponse decryptedResponse = Response.decrypt(response, api);
                if (decryptedResponse != null && decryptedResponse.toByteArray().length() > 0) {
                    this.responseEditor.setContents(decryptedResponse.toByteArray());
                } else {
                    this.responseEditor.setContents(response.toByteArray());
                }
            } catch (Exception e) {
                this.responseEditor.setContents(response.toByteArray());
            }
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return false;
        }

        String reqResponseCombo = ConfigTab.reqresponsecombobox != null ?
            (String) ConfigTab.reqresponsecombobox.getSelectedItem() : "Request";

        if ("Request".equals(reqResponseCombo)) {
            return false;
        }

        return ConfigTab.selectedResponseType != null &&
               !ConfigTab.selectedResponseType.equals("None");
    }

    @Override
    public String caption() {
        return "PyCript";
    }

    @Override
    public Component uiComponent() {
        return responseEditor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return responseEditor.selection().isPresent() ? responseEditor.selection().get() : null;
    }

    @Override
    public boolean isModified() {
        return responseEditor.isModified();
    }

    public void setEditable(boolean editable) {
        responseEditor.setEditable(editable);
    }
}
