package com.pycript.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.LayoutStyle;
import javax.swing.border.LineBorder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class ConfigTab extends JPanel
{
    private final MontoyaApi api;
    private final Logging logging;
    public static String selectedRequestType;

    public static String selectedResponseType;
    public static String selectedRequestEncryptionFile;
    public static String selectedRequestDecryptionFile;
    public static String selectedResponseEncryptionFile;
    public static String selectedResponseDecryptionFile;
    public static JComboBox<String> reqresponsecombobox;
    public static JComboBox<String> requestmethodComboBox;
    public static JTextField languageTextField;
    private String selectedToolType = "";
    private JRadioButton request_parameterValueButton;
    private JRadioButton request_parameterKeyValueButton;
    private JRadioButton response_parameterValueButton;
    private JRadioButton response_parameterKeyValueButton;
    private JButton turnOnButton;
    private JLabel currentStatusLabel;
    private JCheckBox scannerCheckBox;
    private JCheckBox repeaterCheckBox;
    private JCheckBox proxyCheckBox;
    private JCheckBox extenderCheckBox;
    private JCheckBox intruderCheckBox;
    private JRadioButton request_noneButton;
    private JRadioButton Request_Paramter_Ignore_select_noneButton;
    private JRadioButton Response_Paramter_Ignore_select_noneButton;
    private JTextField requestParameterTextField;
    private JTextField responseParameterTextField;
    private JRadioButton requestIncludeParametersButton;
    private JRadioButton requestExcludeParametersButton;
    private JRadioButton responseIncludeParametersButton;
    private JRadioButton responseExcludeParametersButton;

    public ConfigTab(MontoyaApi api)
    {
        super(new BorderLayout());
        this.api = api;
        this.logging = api.logging();
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        JLayeredPane requestTypePane = createRequestTypePane();
        JLayeredPane responseTypePane = createResponseTypePane();
        JLayeredPane additionalSettingsPane = createAdditionalSettingsPane();
        JLayeredPane autoEncryptPane = createAutoEncryptPane();
        JLayeredPane requestParameterPane = createRequestParameterPane();
        JLayeredPane responseParameterPane = createResponseParameterPane();

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.X_AXIS));
        topPanel.add(requestTypePane);
        topPanel.add(Box.createRigidArea(new Dimension(10, 0)));
        topPanel.add(responseTypePane);

        JPanel middlePanel = new JPanel();
        middlePanel.setLayout(new BoxLayout(middlePanel, BoxLayout.X_AXIS));
        middlePanel.add(additionalSettingsPane);
        middlePanel.add(Box.createRigidArea(new Dimension(10, 0)));
        middlePanel.add(autoEncryptPane);

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.X_AXIS));
        bottomPanel.add(requestParameterPane);
        bottomPanel.add(Box.createRigidArea(new Dimension(10, 0)));
        bottomPanel.add(responseParameterPane);

        mainPanel.add(topPanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        mainPanel.add(middlePanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        mainPanel.add(bottomPanel);

        this.add(mainPanel, BorderLayout.CENTER);
    }

    private JLayeredPane createRequestTypePane()
    {
        JLayeredPane requestTypePane = new JLayeredPane();
        requestTypePane.setBorder(new LineBorder(Color.BLACK));

        JLabel label = new JLabel("Request Type");
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        JRadioButton request_completeBodyButton = new JRadioButton("Complete Body");
        request_parameterValueButton = new JRadioButton("Parameter Value");
        request_parameterKeyValueButton = new JRadioButton("Parameter Key and Value");
        request_noneButton = new JRadioButton("None");
        request_noneButton.setSelected(true);

        ButtonGroup group = new ButtonGroup();
        group.add(request_completeBodyButton);
        group.add(request_parameterValueButton);
        group.add(request_parameterKeyValueButton);
        group.add(request_noneButton);


        ActionListener requestTypeListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedRequestEncryptionFile != null && !selectedRequestEncryptionFile.isBlank() &&
                    selectedRequestDecryptionFile != null && !selectedRequestDecryptionFile.isBlank()) {

                    selectedRequestType = e.getActionCommand();


                    if (selectedRequestType.equals("None")) {
                        turnOnButton.setEnabled(false);
                        currentStatusLabel.setText("Current Status: OFF");
                        turnOnButton.setText("Turn ON");
                    }
                    if (!(selectedRequestType.equals("Parameter Value") || selectedRequestType.equals("Parameter Key and Value"))) {
                        Request_Paramter_Ignore_select_noneButton.setSelected(true);

                    }
                } else {
                    selectedRequestType = "None";
                    request_noneButton.setSelected(true);
                    JOptionPane.showMessageDialog(null, "Request Encryption Decryption file is missing", "Error", JOptionPane.ERROR_MESSAGE);


                    turnOnButton.setEnabled(false);

                    currentStatusLabel.setText("Current Status: OFF");
                    turnOnButton.setText("Turn ON");
                }


            }
        };

        request_completeBodyButton.addActionListener(requestTypeListener);
        request_parameterValueButton.addActionListener(requestTypeListener);
        request_parameterKeyValueButton.addActionListener(requestTypeListener);
        request_noneButton.addActionListener(requestTypeListener);

        JLabel encryptionDecryptionFileLabel = new JLabel("Encryption Decryption File for Request");
        JLabel encryptionFileLabel = new JLabel("Encryption File");
        JButton chooseEncryptionFileButton = new JButton("Choose File");
        JLabel encryptionFilePathLabel = new JLabel("/usr/temp");

        ActionListener chooseEncryptionFileListener = new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    JFileChooser fileChooser = new JFileChooser();
                    fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                    fileChooser.setDialogTitle("Select Request Encryption File");


                    int userSelection = fileChooser.showDialog(null, "Select");

                    if (userSelection == JFileChooser.APPROVE_OPTION) {

                        File selectedFile = fileChooser.getSelectedFile();
                        if (selectedFile != null) {
                            selectedRequestEncryptionFile = selectedFile.getAbsolutePath();
                            encryptionFilePathLabel.setText(selectedRequestEncryptionFile);
                        }
                    } else {

                        JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                    }
                }
            };
            chooseEncryptionFileButton.addActionListener(chooseEncryptionFileListener);


        JLabel decryptionFileLabel = new JLabel("Decryption File");
        JButton chooseDecryptionFileButton = new JButton("Choose File");
        JLabel decryptionFilePathLabel = new JLabel("/usr/temp");

        ActionListener chooseDecryptionFileListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setDialogTitle("Select Request Decryption File");


                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {

                    File selectedFile = fileChooser.getSelectedFile();
                    if (selectedFile != null) {
                        selectedRequestDecryptionFile = selectedFile.getAbsolutePath();
                        decryptionFilePathLabel.setText(selectedRequestDecryptionFile);
                    }
                } else {

                    JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };
        chooseDecryptionFileButton.addActionListener(chooseDecryptionFileListener);

        requestTypePane.add(label, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_completeBodyButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_parameterValueButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_parameterKeyValueButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_noneButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(encryptionDecryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(encryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(chooseEncryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(encryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(decryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(chooseDecryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(decryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);

        GroupLayout layout = new GroupLayout(requestTypePane);
        requestTypePane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(label)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(request_completeBodyButton)
                                .addComponent(request_parameterKeyValueButton))
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(request_parameterValueButton)
                                .addComponent(request_noneButton)))
                        .addComponent(encryptionDecryptionFileLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(encryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseEncryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(encryptionFilePathLabel))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(decryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseDecryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(decryptionFilePathLabel)))
                    .addContainerGap(5, Short.MAX_VALUE))
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(label)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(request_completeBodyButton)
                    .addComponent(request_parameterValueButton))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(request_parameterKeyValueButton)
                    .addComponent(request_noneButton))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(encryptionDecryptionFileLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(encryptionFileLabel)
                    .addComponent(chooseEncryptionFileButton)
                    .addComponent(encryptionFilePathLabel))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(decryptionFileLabel)
                    .addComponent(chooseDecryptionFileButton)
                    .addComponent(decryptionFilePathLabel))
                .addContainerGap(5, Short.MAX_VALUE)
        );

        return requestTypePane;
    }

    private JLayeredPane createResponseTypePane()
    {
        JLayeredPane responseTypePane = new JLayeredPane();
        responseTypePane.setBorder(new LineBorder(Color.BLACK));

        JLabel label = new JLabel("Response Type");
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        JRadioButton response_completeBodyButton = new JRadioButton("Complete Body");
        response_parameterValueButton = new JRadioButton("Parameter Value");
        response_parameterKeyValueButton = new JRadioButton("Parameter Key and Value");
        JRadioButton response_noneButton = new JRadioButton("None");
        response_noneButton.setSelected(true);

        ButtonGroup group = new ButtonGroup();
        group.add(response_completeBodyButton);
        group.add(response_parameterValueButton);
        group.add(response_parameterKeyValueButton);
        group.add(response_noneButton);

        ActionListener responseTypeListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedResponseEncryptionFile != null && !selectedResponseEncryptionFile.isBlank() &&
                selectedResponseDecryptionFile != null && !selectedResponseDecryptionFile.isBlank()) {
                selectedResponseType = e.getActionCommand();

                if (!(selectedResponseType.equals("Parameter Value") || selectedResponseType.equals("Parameter Key and Value"))) {
                    Response_Paramter_Ignore_select_noneButton.setSelected(true);

                }
            }
            else {
                selectedResponseType = "None";
                response_noneButton.setSelected(true);
                JOptionPane.showMessageDialog(null, "Response Encryption Decryption file is missing", "Error", JOptionPane.ERROR_MESSAGE);
            }
            }
        };


        response_completeBodyButton.addActionListener(responseTypeListener);
        response_parameterValueButton.addActionListener(responseTypeListener);
        response_parameterKeyValueButton.addActionListener(responseTypeListener);
        response_noneButton.addActionListener(responseTypeListener);


        JLabel encryptionDecryptionFileLabel = new JLabel("Encryption Decryption File for Response");
        JLabel encryptionFileLabel = new JLabel("Encryption File");
        JButton chooseEncryptionFileButton = new JButton("Choose File");
        JLabel encryptionFilePathLabel = new JLabel("/usr/temp");

        ActionListener chooseEncryptionFileListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setDialogTitle("Select Response Encryption File");


                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {

                    File selectedFile = fileChooser.getSelectedFile();
                    if (selectedFile != null) {
                        selectedResponseEncryptionFile = selectedFile.getAbsolutePath();
                        encryptionFilePathLabel.setText(selectedResponseEncryptionFile);
                    }
                } else {

                    JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };
        chooseEncryptionFileButton.addActionListener(chooseEncryptionFileListener);

        JLabel decryptionFileLabel = new JLabel("Decryption File");
        JButton chooseDecryptionFileButton = new JButton("Choose File");
        JLabel decryptionFilePathLabel = new JLabel("/usr/temp");

        ActionListener chooseDecryptionFileListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setDialogTitle("Select Response Decryption File");


                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {

                    File selectedFile = fileChooser.getSelectedFile();
                    if (selectedFile != null) {
                        selectedResponseDecryptionFile = selectedFile.getAbsolutePath();
                        decryptionFilePathLabel.setText(selectedResponseDecryptionFile);
                    }
                } else {

                    JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        chooseDecryptionFileButton.addActionListener(chooseDecryptionFileListener);

        responseTypePane.add(label, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_completeBodyButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_parameterValueButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_parameterKeyValueButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_noneButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(encryptionDecryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(encryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(chooseEncryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(encryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(decryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(chooseDecryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(decryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);

        GroupLayout layout = new GroupLayout(responseTypePane);
        responseTypePane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(label)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(response_completeBodyButton)
                                .addComponent(response_parameterKeyValueButton))
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(response_parameterValueButton)
                                .addComponent(response_noneButton)))
                        .addComponent(encryptionDecryptionFileLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(encryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseEncryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(encryptionFilePathLabel))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(decryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseDecryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(decryptionFilePathLabel)))
                    .addContainerGap(53, Short.MAX_VALUE))
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(label)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(response_completeBodyButton)
                    .addComponent(response_parameterValueButton))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(response_parameterKeyValueButton)
                    .addComponent(response_noneButton))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(encryptionDecryptionFileLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(encryptionFileLabel)
                    .addComponent(chooseEncryptionFileButton)
                    .addComponent(encryptionFilePathLabel))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(decryptionFileLabel)
                    .addComponent(chooseDecryptionFileButton)
                    .addComponent(decryptionFilePathLabel))
                .addContainerGap(53, Short.MAX_VALUE)
        );

        return responseTypePane;
    }

    private JLayeredPane createAdditionalSettingsPane()
    {
        JLayeredPane additionalSettingsPane = new JLayeredPane();
        additionalSettingsPane.setBorder(new LineBorder(Color.BLACK));

        JLabel additionalSettingsLabel = new JLabel("Additional Settings");
        additionalSettingsLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        JLabel languageLabel = new JLabel("Selected Language Binary");
        languageTextField = new JTextField(20);
        languageTextField.setText("usr/bin/python");
        JButton selectLanguageButton = new JButton("Select Language Binary Path");
        JButton clearLanguageButton = new JButton("Clear Language Selected");

        JLabel methodLabel = new JLabel("Encryption Decryption Method");
        requestmethodComboBox = new JComboBox<>(new String[]{"GET", "BODY", "BOTH"});

        JLabel forLabel = new JLabel("Encryption Decryption For");
        reqresponsecombobox = new JComboBox<>(new String[]{"Request", "Response", "BOTH"});

        additionalSettingsPane.add(additionalSettingsLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(languageLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(languageTextField, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(selectLanguageButton, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(clearLanguageButton, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(methodLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(requestmethodComboBox, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(forLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(reqresponsecombobox, JLayeredPane.DEFAULT_LAYER);

        GroupLayout layout = new GroupLayout(additionalSettingsPane);
        additionalSettingsPane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(additionalSettingsLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(languageLabel)
                                .addComponent(methodLabel)
                                .addComponent(forLabel))
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                .addComponent(languageTextField)
                                .addComponent(requestmethodComboBox, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(reqresponsecombobox, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(selectLanguageButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(clearLanguageButton)))
                    .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(additionalSettingsLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(languageLabel)
                    .addComponent(languageTextField)
                    .addComponent(selectLanguageButton)
                    .addComponent(clearLanguageButton))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(methodLabel)
                    .addComponent(requestmethodComboBox))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(forLabel)
                    .addComponent(reqresponsecombobox))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        return additionalSettingsPane;
    }

    private JLayeredPane createAutoEncryptPane()
    {
        JLayeredPane autoEncryptPane = new JLayeredPane();
        autoEncryptPane.setBorder(new LineBorder(Color.BLACK));

        JLabel autoEncryptLabel = new JLabel("Auto Encrypt the Request");
        autoEncryptLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        currentStatusLabel = new JLabel("Current Status: OFF");
        turnOnButton = new JButton("Turn ON");
        turnOnButton.setEnabled(false);

        JLabel cannotTurnOnLabel = new JLabel("Cannot Turn ON Unless Request Type and Tool Type are selected");

        JLabel toolTypeLabel = new JLabel("Auto Encrypt Tool Type");
        scannerCheckBox = new JCheckBox("Scanner");
        repeaterCheckBox = new JCheckBox("Repeater");
        proxyCheckBox = new JCheckBox("Proxy");
        extenderCheckBox = new JCheckBox("Extender");
        intruderCheckBox = new JCheckBox("Intruder");

        ActionListener toolTypeListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                boolean isAnyCheckboxSelected = scannerCheckBox.isSelected() || repeaterCheckBox.isSelected() ||
                                                proxyCheckBox.isSelected() || extenderCheckBox.isSelected() ||
                                                intruderCheckBox.isSelected();

                if (isAnyCheckboxSelected) {

                    if (selectedRequestType == null || selectedRequestType.equals("None")) {
                        JOptionPane.showMessageDialog(null, "Request type is required.", "Warning", JOptionPane.WARNING_MESSAGE);
                        selectedToolType = "";
                        turnOnButton.setEnabled(false);
                        scannerCheckBox.setSelected(false);
                        repeaterCheckBox.setSelected(false);
                        proxyCheckBox.setSelected(false);
                        extenderCheckBox.setSelected(false);
                        intruderCheckBox.setSelected(false);
                        currentStatusLabel.setText("Current Status: OFF");
                        turnOnButton.setText("Turn ON");
                    } else {

                        StringBuilder selectedTools = new StringBuilder();
                        if (scannerCheckBox.isSelected()) selectedTools.append("Scanner, ");
                        if (repeaterCheckBox.isSelected()) selectedTools.append("Repeater, ");
                        if (proxyCheckBox.isSelected()) selectedTools.append("Proxy, ");
                        if (extenderCheckBox.isSelected()) selectedTools.append("Extender, ");
                        if (intruderCheckBox.isSelected()) selectedTools.append("Intruder, ");


                        selectedToolType = selectedTools.substring(0, selectedTools.length() - 2);

                        turnOnButton.setEnabled(true);
                    }
                } else {

                    selectedToolType = "";
                    turnOnButton.setEnabled(false);
                }
            }
        };

        scannerCheckBox.addActionListener(toolTypeListener);
        repeaterCheckBox.addActionListener(toolTypeListener);
        proxyCheckBox.addActionListener(toolTypeListener);
        extenderCheckBox.addActionListener(toolTypeListener);
        intruderCheckBox.addActionListener(toolTypeListener);

        ActionListener turnOnButtonListener = new ActionListener() {
            private boolean isOn = false;

            @Override
            public void actionPerformed(ActionEvent e) {

                if (scannerCheckBox.isSelected() || repeaterCheckBox.isSelected() || proxyCheckBox.isSelected() ||
                    extenderCheckBox.isSelected() || intruderCheckBox.isSelected()) {


                    isOn = !isOn;

                    if (isOn) {
                        currentStatusLabel.setText("Current Status: ON");
                        turnOnButton.setText("Turn OFF");
                    } else {
                        currentStatusLabel.setText("Current Status: OFF");
                        turnOnButton.setText("Turn ON");
                    }
                } else {
                    JOptionPane.showMessageDialog(null, "Please select at least one checkbox to turn ON.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        turnOnButton.addActionListener(turnOnButtonListener);

        autoEncryptPane.add(autoEncryptLabel, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(turnOnButton, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(currentStatusLabel, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(cannotTurnOnLabel, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(toolTypeLabel, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(scannerCheckBox, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(repeaterCheckBox, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(proxyCheckBox, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(extenderCheckBox, JLayeredPane.DEFAULT_LAYER);
        autoEncryptPane.add(intruderCheckBox, JLayeredPane.DEFAULT_LAYER);

        GroupLayout layout = new GroupLayout(autoEncryptPane);
        autoEncryptPane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(autoEncryptLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(turnOnButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(currentStatusLabel))
                        .addComponent(cannotTurnOnLabel)
                        .addComponent(toolTypeLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(scannerCheckBox)
                                .addComponent(proxyCheckBox))
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addComponent(repeaterCheckBox)
                                .addComponent(extenderCheckBox))
                            .addComponent(intruderCheckBox)))
                    .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(autoEncryptLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(turnOnButton)
                    .addComponent(currentStatusLabel))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(cannotTurnOnLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(toolTypeLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(scannerCheckBox)
                    .addComponent(repeaterCheckBox)
                    .addComponent(intruderCheckBox))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(proxyCheckBox)
                    .addComponent(extenderCheckBox))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        return autoEncryptPane;
    }

    private JLayeredPane createRequestParameterPane() {
        JLayeredPane requestParameterPane = new JLayeredPane();
        requestParameterPane.setBorder(new LineBorder(Color.BLACK));

        JLabel titleLabel = new JLabel("Request Parameters to Include/Exclude");
        titleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        requestIncludeParametersButton = new JRadioButton("Include Parameters");
        requestExcludeParametersButton = new JRadioButton("Exclude Parameters");
        Request_Paramter_Ignore_select_noneButton = new JRadioButton("None");
        Request_Paramter_Ignore_select_noneButton.setSelected(true);

        ButtonGroup group = new ButtonGroup();
        group.add(requestIncludeParametersButton);
        group.add(requestExcludeParametersButton);
        group.add(Request_Paramter_Ignore_select_noneButton);

        JLabel infoLabel = new JLabel("Separated by commas, case-sensitive:");
        requestParameterTextField = new JTextField("password,Current_Password");
        requestParameterTextField.setPreferredSize(new Dimension(200, 20));


        ActionListener requestParameterListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!request_parameterValueButton.isSelected() && !request_parameterKeyValueButton.isSelected()) {
                    Request_Paramter_Ignore_select_noneButton.setSelected(true);
                    JOptionPane.showMessageDialog(null, "Request Parameter Type must be selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        requestIncludeParametersButton.addActionListener(requestParameterListener);
        requestExcludeParametersButton.addActionListener(requestParameterListener);


        GroupLayout layout = new GroupLayout(requestParameterPane);
        requestParameterPane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(titleLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(requestIncludeParametersButton)
                    .addComponent(requestExcludeParametersButton)
                    .addComponent(Request_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(requestParameterTextField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                )
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(titleLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(requestIncludeParametersButton)
                    .addComponent(requestExcludeParametersButton)
                    .addComponent(Request_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(requestParameterTextField, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE)
                )
        );

        return requestParameterPane;
    }

    private JLayeredPane createResponseParameterPane() {
        JLayeredPane responseParameterPane = new JLayeredPane();
        responseParameterPane.setBorder(new LineBorder(Color.BLACK));

        JLabel titleLabel = new JLabel("Response Parameters to Include/Exclude");
        titleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        responseIncludeParametersButton = new JRadioButton("Include Parameters");
        responseExcludeParametersButton = new JRadioButton("Exclude Parameters");
        Response_Paramter_Ignore_select_noneButton = new JRadioButton("None");
        Response_Paramter_Ignore_select_noneButton.setSelected(true);

        ButtonGroup group = new ButtonGroup();
        group.add(responseIncludeParametersButton);
        group.add(responseExcludeParametersButton);
        group.add(Response_Paramter_Ignore_select_noneButton);

        JLabel infoLabel = new JLabel("Separated by commas, case-sensitive:");
        responseParameterTextField = new JTextField("password,Current_Password");
        responseParameterTextField.setPreferredSize(new Dimension(200, 20));


        ActionListener responseParameterListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!response_parameterValueButton.isSelected() && !response_parameterKeyValueButton.isSelected()) {
                    Response_Paramter_Ignore_select_noneButton.setSelected(true);
                    JOptionPane.showMessageDialog(null, "Response Parameter Type must be selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        responseIncludeParametersButton.addActionListener(responseParameterListener);
        responseExcludeParametersButton.addActionListener(responseParameterListener);


        GroupLayout layout = new GroupLayout(responseParameterPane);
        responseParameterPane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(titleLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(responseIncludeParametersButton)
                    .addComponent(responseExcludeParametersButton)
                    .addComponent(Response_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(responseParameterTextField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE)
                )
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(titleLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(responseIncludeParametersButton)
                    .addComponent(responseExcludeParametersButton)
                    .addComponent(Response_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(responseParameterTextField, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE)
                )
        );

        return responseParameterPane;
    }

    public static List<String> getParameterList() {
        List<String> paramList = new ArrayList<>();
        ConfigTab instance = getInstance();
        if (instance != null && instance.requestParameterTextField != null) {
            String paramText = instance.requestParameterTextField.getText();
            if (paramText != null && !paramText.trim().isEmpty()) {
                String[] params = paramText.split(",");
                for (String param : params) {
                    String trimmed = param.trim();
                    if (!trimmed.isEmpty()) {
                        paramList.add(trimmed);
                    }
                }
            }
        }
        return paramList;
    }

    public static String getRequestParameterIncludeExcludeType() {
        ConfigTab instance = getInstance();
        if (instance != null) {
            if (instance.requestIncludeParametersButton != null && instance.requestIncludeParametersButton.isSelected()) {
                return "Include Parameters";
            } else if (instance.requestExcludeParametersButton != null && instance.requestExcludeParametersButton.isSelected()) {
                return "Exclude Parameters";
            }
        }
        return "None";
    }

    private static ConfigTab configTabInstance;

    private static ConfigTab getInstance() {
        return configTabInstance;
    }

    public static void setInstance(ConfigTab instance) {
        configTabInstance = instance;
    }
}