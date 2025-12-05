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
