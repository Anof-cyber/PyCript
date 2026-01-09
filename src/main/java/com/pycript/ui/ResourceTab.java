package com.pycript.ui;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import java.awt.*;
import java.io.IOException;
import java.net.URISyntaxException;

public class ResourceTab extends JPanel
{
    public ResourceTab()
    {
        super(new BorderLayout());

        JEditorPane editorPane = new JEditorPane("text/html", getHTMLContent());
        editorPane.setEditable(false);
        editorPane.addHyperlinkListener(new HyperlinkListener() {
            @Override
            public void hyperlinkUpdate(HyperlinkEvent e) {
                if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                    try {
                        Desktop.getDesktop().browse(e.getURL().toURI());
                    } catch (IOException | URISyntaxException ex) {
                    }
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(editorPane);
        this.add(scrollPane, BorderLayout.CENTER);
    }

    private String getHTMLContent()
    {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <style>
                    ul {
                    font-size: 13px;
                    padding-left: 0;
                    }

                    li {
                    margin-bottom: 5px;
                    }
                </style>
            </head>
            <body>
            <h1 style="color: rgb(237, 121, 5)">Documentation for PyCript</h1>

            <h2>Getting Started</h2>
            <h3>Select Encryption and Decryption Files</h3>
            <ul>
                <li>PyCript expects you to provide encryption and decryption files as per your application requirements</li>
                <li>You can write encryption/decryption code in any language: Bash, PowerShell, C, Python, JavaScript, etc.</li>
                <li>PyCript expects the code in a specific format. Get example scripts from <a href="https://github.com/Anof-cyber/PyCript-Template">PyCript Template Repository</a></li>
                <li>For custom code documentation, visit <a href="https://pycript.souravkalal.tech/latest/Scripts/">Writing Custom Scripts</a></li>
            </ul>

            <h3>Configure Language Binary</h3>
            <ul>
                <li>For interpreted languages (Python, Node.js, Ruby, etc.), provide the interpreter path (e.g., C:\\python\\python.exe, /usr/bin/node)</li>
                <li>For compiled binaries (EXE, C, C#, Go, etc.), keep the language path empty</li>
                <li>For shell scripts (Bash, PowerShell), provide the shell path or keep empty if executable directly</li>
            </ul>

            <h3>Select Request/Response Type</h3>
            <ul>
                <li><strong>Complete Body:</strong> Use when your encryption/decryption script handles the full raw request body and headers. PyCript will not parse any parameters. Useful when the whole body is encrypted</li>
                <li><strong>Parameter Value:</strong> Extension will handle parsing of parameters from the request body or URL and send only values to your script. Useful when only parameter values are encrypted (e.g., JSON body)</li>
                <li><strong>Parameter Key and Value:</strong> Extension will handle parsing of parameters and send both keys and values to your script when both are encrypted in the request</li>
            </ul>

            <h3>Debug and Monitor</h3>
            <ul>
                <li>Use the <strong>Log</strong> tab to see how the extension runs your encryption/decryption script</li>
                <li>View the command executed, script output, and any errors from your script</li>
            </ul>

            <h2>Articles</h2>
            <ul>
                <li><a href="https://medium.com/bugbountywriteup/manipulating-encrypted-traffic-using-pycript-b637612528bb">Manipulating Encrypted Traffic using PyCript</a></li>
                <li><a href="https://medium.com/bugbountywriteup/bypassing-asymmetric-client-side-encryption-without-private-key-822ed0d8aeb6">Bypassing Asymmetric Client Side Encryption Without Private Key</a></li>
            </ul>

            <h2>Documentation</h2>
            <ul>
                <li><a href="https://pycript.souravkalal.tech/">PyCript Documentation</a></li>
            </ul>

            <h2>Repository</h2>
            <ul>
            <li><a href="https://github.com/Anof-cyber/PyCript-Template">PyCript Template Repository with common encryption decrpytion script for PyCript</a></li>
            <li><a href="https://github.com/Anof-cyber/PyCript">GitHub Repository</a></li>
            </ul>

            <h2>Social Media</h2>
            <ul>
            <li><a href="https://twitter.com/ano_f_">Twitter Profile</a></li>
            </ul>
            </body>
            </html>
        """;
    }
}
