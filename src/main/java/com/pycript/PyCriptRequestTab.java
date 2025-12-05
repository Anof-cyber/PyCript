package com.pycript;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import javax.swing.*;
import java.awt.*;

public class PyCriptRequestTab implements HttpRequestEditorProvider
{
    private final MontoyaApi api;

    public PyCriptRequestTab(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext)
    {
        return new RequestHttpRequestEditor(api, creationContext);
    }

   
}
