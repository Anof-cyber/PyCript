package com.pycript;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.pycript.ui.ConfigTab;
import com.pycript.ui.DecryptedRequestTab;
import com.pycript.ui.LogTab;
import com.pycript.ui.ResourceTab;
import com.pycript.EncDec.Request;
import com.pycript.websocket.WebSocketEditorProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public class PyCript implements BurpExtension

{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("PyCript");

        Logging logging = api.logging();
        logging.logToOutput("Author: Sourav Kalal");
        logging.logToOutput("VERSION: 2.0");
        logging.logToOutput("GitHub - https://github.com/Anof-cyber/PyCript");
        logging.logToOutput("Website - https://souravkalal.tech/");
        logging.logToOutput("Documentation - https://pycript.souravkalal.tech/");

        api.userInterface().registerSuiteTab("PyCript", new PyCriptTab(api));
        api.userInterface().registerHttpRequestEditorProvider(new PyCriptRequestTab(api));
        api.userInterface().registerHttpResponseEditorProvider(new PyCriptResponseTab(api));
        api.userInterface().registerContextMenuItemsProvider(new PyCriptContextMenu(api));
        api.userInterface().registerWebSocketMessageEditorProvider(new WebSocketEditorProvider(api));
    }

    private static class PyCriptContextMenu implements ContextMenuItemsProvider
    {
        private final MontoyaApi api;

        public PyCriptContextMenu(MontoyaApi api)
        {
            this.api = api;
        }

        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event)
        {
            List<Component> menuItems = new ArrayList<>();

            if (event.messageEditorRequestResponse().isPresent())
            {
                MessageEditorHttpRequestResponse messageEditor = event.messageEditorRequestResponse().get();

                JMenuItem decryptRequestItem = new JMenuItem("Decrypt Request");
                decryptRequestItem.addActionListener(e -> decryptRequestFromMenu(messageEditor));
                menuItems.add(decryptRequestItem);
            }

            return menuItems;
        }

        private void decryptRequestFromMenu(MessageEditorHttpRequestResponse messageEditor)
        {
            if (ConfigTab.selectedRequestType == null || ConfigTab.selectedRequestType.equals("None"))
            {
                return;
            }

            HttpRequest originalRequest = messageEditor.requestResponse().request();
            if (originalRequest == null)
            {
                return;
            }

            try
            {
                HttpRequest decryptedRequest = Request.decrypt(originalRequest, api);
                String method = originalRequest.method();
                String url = originalRequest.url();

                HttpResponse response = messageEditor.requestResponse().response();

                DecryptedRequestTab tab = DecryptedRequestTab.getInstance();
                if (tab != null) {
                    tab.addEntry(method, url, decryptedRequest, response);
                }
            }
            catch (Exception ex)
            {
            }
        }
    }

    private static class PyCriptTab extends JPanel
    {
        private final MontoyaApi api;

        public PyCriptTab(MontoyaApi api)
        {
            super(new BorderLayout());
            this.api = api;
            JTabbedPane tabbedPane = new JTabbedPane();

            ConfigTab configTab = new ConfigTab(this.api);
            ConfigTab.setInstance(configTab);
            tabbedPane.addTab("Config", configTab);
            tabbedPane.addTab("Decrypted Request", new DecryptedRequestTab(this.api));
            tabbedPane.addTab("Log", new LogTab(this.api));
            tabbedPane.addTab("Resource", new ResourceTab());

            this.add(tabbedPane, BorderLayout.CENTER);
        }
    }
}