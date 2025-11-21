package com.pycript;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.pycript.ui.ConfigTab;
import com.pycript.ui.DecryptedRequestTab;
import com.pycript.ui.LogTab;
import com.pycript.EncDec.Request;

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
        logging.logToOutput("VERSION: 1.1");
        logging.logToOutput("GitHub - https://github.com/Anof-cyber/PyCript");
        logging.logToOutput("Website - https://souravkalal.tech/");
        logging.logToOutput("Documentation - https://pycript.souravkalal.tech/");

        api.userInterface().registerSuiteTab("PyCript", new PyCriptTab(api));
        api.userInterface().registerHttpRequestEditorProvider(new PyCriptRequestTab(api));
        api.userInterface().registerHttpResponseEditorProvider(new PyCriptResponseTab(api));
        api.userInterface().registerContextMenuItemsProvider(new PyCriptContextMenu(api));
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
                api.logging().logToOutput("Request decryption is not configured");
                return;
            }

            HttpRequest originalRequest = messageEditor.requestResponse().request();
            if (originalRequest == null)
            {
                api.logging().logToOutput("No request found");
                return;
            }

            try
            {
                HttpRequest decryptedRequest = Request.decrypt(originalRequest, api);
                api.logging().logToOutput(decryptedRequest.toString());
            }
            catch (Exception ex)
            {
                api.logging().logToError("Error decrypting request: " + ex.getMessage());
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
            tabbedPane.addTab("Decrypted Request", new DecryptedRequestTab());
            tabbedPane.addTab("Log", new LogTab(this.api));

            this.add(tabbedPane, BorderLayout.CENTER);
        }
    }
}