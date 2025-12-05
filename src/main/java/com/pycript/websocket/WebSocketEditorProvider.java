package com.pycript.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;

public class WebSocketEditorProvider implements WebSocketMessageEditorProvider
{
    private final MontoyaApi api;

    public WebSocketEditorProvider(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext creationContext)
    {
        return new WebSocketMessageEditor(api, creationContext);
    }
}
