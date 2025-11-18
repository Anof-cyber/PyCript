package com.pycript;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import com.pycript.ui.ConfigTab;
import com.pycript.ui.DecryptedRequestTab;
import com.pycript.ui.LogTab;

import javax.swing.*;
import java.awt.*;

public class PyCript implements BurpExtension

{
    @Override
    public void initialize(MontoyaApi api)
    {
        // set extension name
        api.extension().setName("PyCript");

        Logging logging = api.logging();
        logging.logToOutput("Author: Sourav Kalal");
        logging.logToOutput("VERSION: 1.1");
        logging.logToOutput("GitHub - https://github.com/Anof-cyber/PyCript");
        logging.logToOutput("Website - https://souravkalal.tech/");
        logging.logToOutput("Documentation - https://pycript.souravkalal.tech/");

        // Add a new tab to the Burp Suite UI
        api.userInterface().registerSuiteTab("PyCript", new PyCriptTab(api));
        api.userInterface().registerHttpRequestEditorProvider(new PyCriptRequestTab(api));
    }

    private static class PyCriptTab extends JPanel
    {
        private final MontoyaApi api;

        public PyCriptTab(MontoyaApi api)
        {
            super(new BorderLayout());
            this.api = api;
            JTabbedPane tabbedPane = new JTabbedPane();

            // Add three tabs
            tabbedPane.addTab("Config", new ConfigTab(this.api));
            tabbedPane.addTab("Decrypted Request", new DecryptedRequestTab());
            tabbedPane.addTab("Log", new LogTab(this.api));

            this.add(tabbedPane, BorderLayout.CENTER);
        }
    }
}