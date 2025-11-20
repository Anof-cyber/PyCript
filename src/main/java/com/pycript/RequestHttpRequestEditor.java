package com.pycript;

import java.util.Optional;

import com.pycript.ui.ConfigTab;
import com.pycript.EncDec.Request;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.utilities.Base64EncodingOptions;
import burp.api.montoya.http.message.HttpRequestResponse;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import java.awt.Component;

class RequestHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final RawEditor requestEditor;
    private HttpRequestResponse requestResponse;


    RequestHttpRequestEditor (MontoyaApi api, EditorCreationContext creationContext) {
        this.api = api;
        requestEditor = api.userInterface().createRawEditor(EditorOptions.WRAP_LINES, EditorOptions.SHOW_NON_PRINTABLE_CHARACTERS);
    }

    @Override
    public HttpRequest getRequest()
    {
        HttpRequest request;
        request = requestResponse.request();
        HttpRequest encryptedRequest = Request.encrypt(request, api);
        return encryptedRequest;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse)
    {
        this.requestResponse = requestResponse;
        HttpRequest request;

        if (requestResponse.request() == null || requestResponse.request().toByteArray().length() == 0) {
            this.requestEditor.setEditable(false);
        }

        else {
            request = requestResponse.request();

           if (!request.isInScope()) {

            this.requestEditor.setEditable(false);
            this.requestEditor.setContents(ByteArray.byteArray(api.utilities().byteUtils().convertFromString("Request is out of scope")));

            } else {

                this.requestEditor.setEditable(true);
                Request req = new Request();
                HttpRequest decryptedRequest = Request.decrypt(request, api);
                this.requestEditor.setContents(decryptedRequest.toByteArray());

            }
        }


        //this.requestEditor.setContents();

    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse)
    {
        return !ConfigTab.selectedRequestType.equals("None") && !ConfigTab.reqresponsecombobox.getSelectedItem().equals("Response");
    }

    @Override
    public String caption()
    {
        return "PyCript";
    }

    @Override
    public Component uiComponent()
    {
        return requestEditor.uiComponent();
    }

    @Override
    public Selection selectedData()
    {
        return requestEditor.selection().isPresent() ? requestEditor.selection().get() : null;
    }

    @Override
    public boolean isModified()
    {
        return requestEditor.isModified();
    }

    public void setEditable(boolean editable)
    {
        requestEditor.setEditable(editable);
    }


}
