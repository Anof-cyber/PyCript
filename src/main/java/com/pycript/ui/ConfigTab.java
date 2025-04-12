package com.pycript.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

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
    private String selectedToolType = ""; // Initially empty
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
        topPanel.add(Box.createRigidArea(new Dimension(10, 0))); // Add space between the panes
        topPanel.add(responseTypePane);

        JPanel middlePanel = new JPanel();
        middlePanel.setLayout(new BoxLayout(middlePanel, BoxLayout.X_AXIS));
        middlePanel.add(additionalSettingsPane);
        middlePanel.add(Box.createRigidArea(new Dimension(10, 0))); // Add space between the panes
        middlePanel.add(autoEncryptPane);

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.X_AXIS));
        bottomPanel.add(requestParameterPane);
        bottomPanel.add(Box.createRigidArea(new Dimension(10, 0))); // Add space between the panes
        bottomPanel.add(responseParameterPane);

        mainPanel.add(topPanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10))); // Add space between the top and middle panels
        mainPanel.add(middlePanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10))); // Add space between the middle and bottom panels
        mainPanel.add(bottomPanel);

        this.add(mainPanel, BorderLayout.CENTER);
    }

    private JLayeredPane createRequestTypePane()
    {
        JLayeredPane requestTypePane = new JLayeredPane();
        requestTypePane.setBorder(new LineBorder(Color.BLACK)); // Add black border

        JLabel label = new JLabel("Request Type");
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14)); // Example font
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

        // Add action listeners to update the selectedRequestType variable
        ActionListener requestTypeListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedRequestEncryptionFile != null && !selectedRequestEncryptionFile.isBlank() &&
                    selectedRequestDecryptionFile != null && !selectedRequestDecryptionFile.isBlank()) {
                    
                    selectedRequestType = e.getActionCommand();

                    // If "None" is selected, reset tool type and disable the turnOnButton
                    if (selectedRequestType.equals("None")) {
                        turnOnButton.setEnabled(false); // Disable the turnOnButton
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

                    // Reset tool type and disable the turnOnButton
                    turnOnButton.setEnabled(false); // Disable the turnOnButton
                    
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

                    // Show the file chooser dialog and capture the user's action
                    int userSelection = fileChooser.showDialog(null, "Select");

                    if (userSelection == JFileChooser.APPROVE_OPTION) {
                        // Get the selected file
                        File selectedFile = fileChooser.getSelectedFile();
                        if (selectedFile != null) {
                            selectedRequestEncryptionFile = selectedFile.getAbsolutePath(); // Get the full file path
                            encryptionFilePathLabel.setText(selectedRequestEncryptionFile); // Update the label with the file path
                        }
                    } else {
                        // Handle the cancel action
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

                // Show the file chooser dialog and capture the user's action
                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    // Get the selected file
                    File selectedFile = fileChooser.getSelectedFile();
                    if (selectedFile != null) {
                        selectedRequestDecryptionFile = selectedFile.getAbsolutePath(); // Get the full file path
                        decryptionFilePathLabel.setText(selectedRequestDecryptionFile); // Update the label with the file path
                    }
                } else {
                    // Handle the cancel action
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
        responseTypePane.setBorder(new LineBorder(Color.BLACK)); // Add black border

        JLabel label = new JLabel("Response Type");
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        JRadioButton response_completeBodyButton = new JRadioButton("Complete Body");
        response_parameterValueButton = new JRadioButton("Parameter Value");
        response_parameterKeyValueButton = new JRadioButton("Parameter Key and Value");
        JRadioButton response_noneButton = new JRadioButton("None");
        response_noneButton.setSelected(true); // Default selection

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

                // Show the file chooser dialog and capture the user's action
                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    // Get the selected file
                    File selectedFile = fileChooser.getSelectedFile();
                    if (selectedFile != null) {
                        selectedResponseEncryptionFile = selectedFile.getAbsolutePath(); // Get the full file path
                        encryptionFilePathLabel.setText(selectedResponseEncryptionFile); // Update the label with the file path
                    }
                } else {
                    // Handle the cancel action
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

                // Show the file chooser dialog and capture the user's action
                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    // Get the selected file
                    File selectedFile = fileChooser.getSelectedFile();
                    if (selectedFile != null) {
                        selectedResponseDecryptionFile = selectedFile.getAbsolutePath(); // Get the full file path
                        decryptionFilePathLabel.setText(selectedResponseDecryptionFile); // Update the label with the file path
                    }
                } else {
                    // Handle the cancel action
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
        additionalSettingsPane.setBorder(new LineBorder(Color.BLACK)); // Add black border

        JLabel additionalSettingsLabel = new JLabel("Additional Settings");
        additionalSettingsLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        JLabel languageLabel = new JLabel("Selected Language Binary");
        JTextField languageTextField = new JTextField(20);
        languageTextField.setText("usr/bin/python");
        JButton selectLanguageButton = new JButton("Select Language Binary Path");
        JButton clearLanguageButton = new JButton("Clear Language Selected");

        JLabel methodLabel = new JLabel("Encryption Decryption Method");
        JComboBox<String> methodComboBox = new JComboBox<>(new String[]{"GET", "BODY", "BOTH"});

        JLabel forLabel = new JLabel("Encryption Decryption For");
        JComboBox<String> forComboBox = new JComboBox<>(new String[]{"Request", "Response", "BOTH"});

        additionalSettingsPane.add(additionalSettingsLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(languageLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(languageTextField, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(selectLanguageButton, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(clearLanguageButton, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(methodLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(methodComboBox, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(forLabel, JLayeredPane.DEFAULT_LAYER);
        additionalSettingsPane.add(forComboBox, JLayeredPane.DEFAULT_LAYER);

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
                                .addComponent(methodComboBox, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(forComboBox, 0, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
                    .addComponent(methodComboBox))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(forLabel)
                    .addComponent(forComboBox))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        return additionalSettingsPane;
    }

    private JLayeredPane createAutoEncryptPane()
    {
        JLayeredPane autoEncryptPane = new JLayeredPane();
        autoEncryptPane.setBorder(new LineBorder(Color.BLACK)); // Add black border

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
                // Check if any checkbox is selected
                boolean isAnyCheckboxSelected = scannerCheckBox.isSelected() || repeaterCheckBox.isSelected() ||
                                                proxyCheckBox.isSelected() || extenderCheckBox.isSelected() ||
                                                intruderCheckBox.isSelected();

                if (isAnyCheckboxSelected) {
                    // Check if request_noneButton is selected
                    if (selectedRequestType == null || selectedRequestType.equals("None")) {
                        JOptionPane.showMessageDialog(null, "Request type is required.", "Warning", JOptionPane.WARNING_MESSAGE);
                        selectedToolType = ""; // Clear the selected tool type
                        turnOnButton.setEnabled(false); // Disable the turnOnButton
                        scannerCheckBox.setSelected(false);
                        repeaterCheckBox.setSelected(false);
                        proxyCheckBox.setSelected(false);
                        extenderCheckBox.setSelected(false);
                        intruderCheckBox.setSelected(false);
                        currentStatusLabel.setText("Current Status: OFF");
                        turnOnButton.setText("Turn ON");
                    } else {
                        // Store the selected checkbox values in the variable
                        StringBuilder selectedTools = new StringBuilder();
                        if (scannerCheckBox.isSelected()) selectedTools.append("Scanner, ");
                        if (repeaterCheckBox.isSelected()) selectedTools.append("Repeater, ");
                        if (proxyCheckBox.isSelected()) selectedTools.append("Proxy, ");
                        if (extenderCheckBox.isSelected()) selectedTools.append("Extender, ");
                        if (intruderCheckBox.isSelected()) selectedTools.append("Intruder, ");

                        // Remove the trailing comma and space
                        selectedToolType = selectedTools.substring(0, selectedTools.length() - 2);

                        turnOnButton.setEnabled(true); // Enable the turnOnButton
                    }
                } else {
                    // No checkbox is selected
                    selectedToolType = ""; // Clear the selected tool type
                    turnOnButton.setEnabled(false); // Disable the turnOnButton
                }
            }
        };

        scannerCheckBox.addActionListener(toolTypeListener);
        repeaterCheckBox.addActionListener(toolTypeListener);
        proxyCheckBox.addActionListener(toolTypeListener);
        extenderCheckBox.addActionListener(toolTypeListener);
        intruderCheckBox.addActionListener(toolTypeListener);

        ActionListener turnOnButtonListener = new ActionListener() {
            private boolean isOn = false; // Track the current state of the button

            @Override
            public void actionPerformed(ActionEvent e) {
                // Check if at least one checkbox is selected
                if (scannerCheckBox.isSelected() || repeaterCheckBox.isSelected() || proxyCheckBox.isSelected() ||
                    extenderCheckBox.isSelected() || intruderCheckBox.isSelected()) {
                    
                    // Toggle the state
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
        requestParameterPane.setBorder(new LineBorder(Color.BLACK)); // Add black border

        JLabel titleLabel = new JLabel("Request Parameters to Include/Exclude");
        titleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        JRadioButton includeParametersButton = new JRadioButton("Include Parameters");
        JRadioButton excludeParametersButton = new JRadioButton("Exclude Parameters");
        Request_Paramter_Ignore_select_noneButton = new JRadioButton("None");
        Request_Paramter_Ignore_select_noneButton.setSelected(true); // Default selection

        ButtonGroup group = new ButtonGroup();
        group.add(includeParametersButton);
        group.add(excludeParametersButton);
        group.add(Request_Paramter_Ignore_select_noneButton);

        JLabel infoLabel = new JLabel("Separated by commas, case-sensitive:");
        JTextField parameterTextField = new JTextField("password,Current_Password");
        parameterTextField.setPreferredSize(new Dimension(200, 20)); // Set width to 200px and height to 20px

        // Add a common listener for the radio buttons
        ActionListener requestParameterListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!request_parameterValueButton.isSelected() && !request_parameterKeyValueButton.isSelected()) {
                    Request_Paramter_Ignore_select_noneButton.setSelected(true); // Reset to "None"
                    JOptionPane.showMessageDialog(null, "Request Parameter Type must be selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        includeParametersButton.addActionListener(requestParameterListener);
        excludeParametersButton.addActionListener(requestParameterListener);

        // Layout setup
        GroupLayout layout = new GroupLayout(requestParameterPane);
        requestParameterPane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(titleLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(includeParametersButton)
                    .addComponent(excludeParametersButton)
                    .addComponent(Request_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(parameterTextField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE) // Set fixed width
                )
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(titleLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(includeParametersButton)
                    .addComponent(excludeParametersButton)
                    .addComponent(Request_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(parameterTextField, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE) // Set fixed height
                )
        );

        return requestParameterPane;
    }

    private JLayeredPane createResponseParameterPane() {
        JLayeredPane responseParameterPane = new JLayeredPane();
        responseParameterPane.setBorder(new LineBorder(Color.BLACK)); // Add black border

        JLabel titleLabel = new JLabel("Response Parameters to Include/Exclude");
        titleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        JRadioButton includeParametersButton = new JRadioButton("Include Parameters");
        JRadioButton excludeParametersButton = new JRadioButton("Exclude Parameters");
        Response_Paramter_Ignore_select_noneButton = new JRadioButton("None");
        Response_Paramter_Ignore_select_noneButton.setSelected(true); // Default selection

        ButtonGroup group = new ButtonGroup();
        group.add(includeParametersButton);
        group.add(excludeParametersButton);
        group.add(Response_Paramter_Ignore_select_noneButton);

        JLabel infoLabel = new JLabel("Separated by commas, case-sensitive:");
        JTextField parameterTextField = new JTextField("password,Current_Password");
        parameterTextField.setPreferredSize(new Dimension(200, 20)); // Set width to 200px and height to 20px

        // Add a common listener for the radio buttons
        ActionListener responseParameterListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!response_parameterValueButton.isSelected() && !response_parameterKeyValueButton.isSelected()) {
                    Response_Paramter_Ignore_select_noneButton.setSelected(true); // Reset to "None"
                    JOptionPane.showMessageDialog(null, "Response Parameter Type must be selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        includeParametersButton.addActionListener(responseParameterListener);
        excludeParametersButton.addActionListener(responseParameterListener);

        // Layout setup
        GroupLayout layout = new GroupLayout(responseParameterPane);
        responseParameterPane.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(titleLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(includeParametersButton)
                    .addComponent(excludeParametersButton)
                    .addComponent(Response_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(parameterTextField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE) // Set fixed width
                )
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(titleLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(includeParametersButton)
                    .addComponent(excludeParametersButton)
                    .addComponent(Response_Paramter_Ignore_select_noneButton))
                .addComponent(infoLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(parameterTextField, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE) // Set fixed height
                )
        );

        return responseParameterPane;
    }
}