package com.pycript.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import burp.api.montoya.MontoyaApi;

public class LogTab extends JPanel {

    private static LogTab instance;
    private final MontoyaApi api;
    private JCheckBox errorLogCheckbox;
    private JButton clearButton;
    private JTextArea errorLogTextArea;
    private JScrollPane scrollPane;

    public LogTab(MontoyaApi api) {
        this.api = api;
        instance = this;
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());
        setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));

        errorLogCheckbox = new JCheckBox("Allow logging encryption/decryption command stderr and stdout");
        errorLogCheckbox.setFont(errorLogCheckbox.getFont().deriveFont(Font.PLAIN, 12f));

        clearButton = new JButton("Clear");
        clearButton.setPreferredSize(new Dimension(80, 25));
        clearButton.setFont(clearButton.getFont().deriveFont(Font.PLAIN, 12f));

        topPanel.add(errorLogCheckbox);
        topPanel.add(clearButton);

        add(topPanel, BorderLayout.NORTH);

        errorLogTextArea = new JTextArea(30, 110);
        errorLogTextArea.setBackground(new Color(32, 32, 32));
        errorLogTextArea.setForeground(Color.WHITE);
        errorLogTextArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        errorLogTextArea.setLineWrap(true);
        errorLogTextArea.setWrapStyleWord(false);
        errorLogTextArea.setEditable(true);
        errorLogTextArea.setCaretColor(Color.WHITE);

        scrollPane = new JScrollPane(errorLogTextArea);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(javax.swing.BorderFactory.createEmptyBorder());

        add(scrollPane, BorderLayout.CENTER);

        setupActionListeners();
    }

    private void setupActionListeners() {
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                errorLogTextArea.setText("");
            }
        });
    }

    public void appendLog(String message) {
        SwingUtilities.invokeLater(() -> {
            errorLogTextArea.append(message + "\n");
            errorLogTextArea.setCaretPosition(errorLogTextArea.getDocument().getLength());
        });
    }

    public static LogTab getInstance() {
        return instance;
    }

    public boolean isLoggingEnabled() {
        return errorLogCheckbox.isSelected();
    }

    public void clearLogs() {
        errorLogTextArea.setText("");
    }
}
