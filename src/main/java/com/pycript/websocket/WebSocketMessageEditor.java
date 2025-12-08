package com.pycript.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import com.pycript.ui.ConfigTab;
import com.pycript.EncDec.Execution;
import org.apache.commons.lang3.tuple.Pair;

import java.awt.*;

public class WebSocketMessageEditor implements ExtensionProvidedWebSocketMessageEditor
{
    private final RawEditor editor;
    private final MontoyaApi api;

    public WebSocketMessageEditor(MontoyaApi api, EditorCreationContext creationContext)
    {
        this.api = api;

        if (creationContext.editorMode() == EditorMode.READ_ONLY)
        {
            editor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        }
        else {
            editor = api.userInterface().createRawEditor();
        }
    }

    @Override
    public ByteArray getMessage() {
        if (!ConfigTab.webSocketEnabled || ConfigTab.webSocketEncryptionFile == null || ConfigTab.webSocketEncryptionFile.isBlank()) {
            return editor.getContents();
        }

        try {
            Pair<byte[], String> result = Execution.executeCommand(
                ConfigTab.languageTextField != null ? ConfigTab.languageTextField.getText() : "",
                ConfigTab.webSocketEncryptionFile,
                editor.getContents().getBytes(),
                ""
            );

            if (result != null) {
                return ByteArray.byteArray(result.getLeft());
            }
        } catch (Exception e) {
        }

        return editor.getContents();
    }

    @Override
    public void setMessage(WebSocketMessage message) {
        // Check if the WebSocket upgrade request is in scope
        if (message.upgradeRequest() == null || !api.scope().isInScope(message.upgradeRequest().url())) {
            editor.setEditable(false);
            editor.setContents(ByteArray.byteArray(api.utilities().byteUtils().convertFromString("WebSocket is out of scope")));
            return;
        }

        editor.setEditable(true);

        if (!ConfigTab.webSocketEnabled || ConfigTab.webSocketDecryptionFile == null || ConfigTab.webSocketDecryptionFile.isBlank()) {
            editor.setContents(message.payload());
            return;
        }

        try {
            Pair<byte[], String> result = Execution.executeCommand(
                ConfigTab.languageTextField != null ? ConfigTab.languageTextField.getText() : "",
                ConfigTab.webSocketDecryptionFile,
                message.payload().getBytes(),
                ""
            );

            if (result != null) {
                editor.setContents(ByteArray.byteArray(result.getLeft()));
                return;
            }
        } catch (Exception e) {
        }

        editor.setContents(message.payload());
    }

    @Override
    public boolean isEnabledFor(WebSocketMessage message) {
        return ConfigTab.webSocketEnabled;
    }

    @Override
    public String caption() {
        return "PyCript";
    }

    @Override
    public Component uiComponent() {
        return editor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return editor.selection().orElse(null);
    }

    @Override
    public boolean isModified() {
        return editor.isModified();
    }
}
