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
import javax.swing.JScrollPane;
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
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.Registration;
import com.pycript.EncDec.Request;
import com.pycript.EncDec.AutoEncryptHttpHandler;

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
    public static String webSocketEncryptionFile;
    public static String webSocketDecryptionFile;
    public static boolean webSocketEnabled = false;
    public static JComboBox<String> reqresponsecombobox;
    public static JComboBox<String> requestmethodComboBox;
    public static JTextField languageTextField;
    private String selectedToolType = "";
    private List<ToolType> selectedToolTypes = new ArrayList<>();
    private Registration httpHandlerRegistration;
    private JRadioButton request_completeBodyButton;
    private JRadioButton request_parameterValueButton;
    private JRadioButton request_parameterKeyValueButton;
    private JRadioButton response_completeBodyButton;
    private JRadioButton response_parameterValueButton;
    private JRadioButton response_parameterKeyValueButton;
    private JRadioButton response_noneButton;
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
    private JLabel requestEncryptionFilePathLabel;
    private JLabel requestDecryptionFilePathLabel;
    private JLabel responseEncryptionFilePathLabel;
    private JLabel responseDecryptionFilePathLabel;
    private JButton webSocketToggleButton;
    private JLabel webSocketStatusLabel;
    private JLabel webSocketEncryptionFilePathLabel;
    private JLabel webSocketDecryptionFilePathLabel;

    public ConfigTab(MontoyaApi api)
    {
        super(new BorderLayout());
        this.api = api;
        this.logging = api.logging();
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        JLayeredPane requestTypePane = createRequestTypePane();
        JLayeredPane responseTypePane = createResponseTypePane();
        JLayeredPane webSocketPane = createWebSocketPane();
        JLayeredPane additionalSettingsPane = createAdditionalSettingsPane();
        JLayeredPane autoEncryptPane = createAutoEncryptPane();

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.X_AXIS));
        topPanel.add(requestTypePane);
        topPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        topPanel.add(responseTypePane);

        JPanel middlePanel = new JPanel();
        middlePanel.setLayout(new BoxLayout(middlePanel, BoxLayout.X_AXIS));
        middlePanel.add(additionalSettingsPane);
        middlePanel.add(Box.createRigidArea(new Dimension(5, 0)));
        middlePanel.add(autoEncryptPane);

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.X_AXIS));
        bottomPanel.add(webSocketPane);
        bottomPanel.add(Box.createHorizontalGlue());

        mainPanel.add(topPanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        mainPanel.add(middlePanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        mainPanel.add(bottomPanel);

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        this.add(scrollPane, BorderLayout.CENTER);

        loadSettings();
    }

    private JLayeredPane createRequestTypePane()
    {
        JLayeredPane requestTypePane = new JLayeredPane();
        requestTypePane.setBorder(new LineBorder(Color.GRAY, 1));

        JLabel label = new JLabel("Request Type");
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        label.setForeground(new Color(0xFF, 0x66, 0x33));
        request_completeBodyButton = new JRadioButton("Complete Body");
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
                    api.persistence().preferences().setString("pycript.request.type", selectedRequestType);
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
        encryptionDecryptionFileLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        encryptionDecryptionFileLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        JLabel encryptionFileLabel = new JLabel("Encryption File");
        JButton chooseEncryptionFileButton = new JButton("Choose File");
        requestEncryptionFilePathLabel = new JLabel("/usr/temp");

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
                            requestEncryptionFilePathLabel.setText(selectedRequestEncryptionFile);
                            api.persistence().preferences().setString("pycript.request.encryption.file", selectedRequestEncryptionFile);
                        }
                    } else {

                        JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                    }
                }
            };
            chooseEncryptionFileButton.addActionListener(chooseEncryptionFileListener);


        JLabel decryptionFileLabel = new JLabel("Decryption File");
        JButton chooseDecryptionFileButton = new JButton("Choose File");
        requestDecryptionFilePathLabel = new JLabel("/usr/temp");

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
                        requestDecryptionFilePathLabel.setText(selectedRequestDecryptionFile);
                        api.persistence().preferences().setString("pycript.request.decryption.file", selectedRequestDecryptionFile);
                    }
                } else {

                    JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };
        chooseDecryptionFileButton.addActionListener(chooseDecryptionFileListener);

        // Request Parameter Controls
        JLabel parameterTitleLabel = new JLabel("Parameters to Include/Exclude");
        parameterTitleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        parameterTitleLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        requestIncludeParametersButton = new JRadioButton("Include");
        requestExcludeParametersButton = new JRadioButton("Exclude");
        Request_Paramter_Ignore_select_noneButton = new JRadioButton("None");
        Request_Paramter_Ignore_select_noneButton.setSelected(true);

        ButtonGroup parameterGroup = new ButtonGroup();
        parameterGroup.add(requestIncludeParametersButton);
        parameterGroup.add(requestExcludeParametersButton);
        parameterGroup.add(Request_Paramter_Ignore_select_noneButton);

        JLabel parameterInfoLabel = new JLabel("Separated by commas, case-sensitive:");
        requestParameterTextField = new JTextField("password,Current_Password");
        requestParameterTextField.setPreferredSize(new Dimension(200, 20));

        ActionListener requestParameterListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!request_parameterValueButton.isSelected() && !request_parameterKeyValueButton.isSelected()) {
                    Request_Paramter_Ignore_select_noneButton.setSelected(true);
                    JOptionPane.showMessageDialog(null, "Request Parameter Type must be selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
                api.persistence().preferences().setString("pycript.request.include.exclude", getRequestParameterIncludeExcludeType());
            }
        };

        requestIncludeParametersButton.addActionListener(requestParameterListener);
        requestExcludeParametersButton.addActionListener(requestParameterListener);
        Request_Paramter_Ignore_select_noneButton.addActionListener(e -> api.persistence().preferences().setString("pycript.request.include.exclude", "None"));
        requestParameterTextField.addActionListener(e -> api.persistence().preferences().setString("pycript.request.parameter.text", requestParameterTextField.getText()));

        requestTypePane.add(label, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_completeBodyButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_parameterValueButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_parameterKeyValueButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(request_noneButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(encryptionDecryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(encryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(chooseEncryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(requestEncryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(decryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(chooseDecryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(requestDecryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(parameterTitleLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(requestIncludeParametersButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(requestExcludeParametersButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(Request_Paramter_Ignore_select_noneButton, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(parameterInfoLabel, JLayeredPane.DEFAULT_LAYER);
        requestTypePane.add(requestParameterTextField, JLayeredPane.DEFAULT_LAYER);

        GroupLayout layout = new GroupLayout(requestTypePane);
        requestTypePane.setLayout(layout);
        layout.setAutoCreateGaps(false);
        layout.setAutoCreateContainerGaps(false);

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
                            .addComponent(requestEncryptionFilePathLabel))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(decryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseDecryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(requestDecryptionFilePathLabel))
                        .addComponent(parameterTitleLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(requestIncludeParametersButton)
                            .addComponent(requestExcludeParametersButton)
                            .addComponent(Request_Paramter_Ignore_select_noneButton))
                        .addComponent(parameterInfoLabel)
                        .addComponent(requestParameterTextField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE))
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
                    .addComponent(requestEncryptionFilePathLabel))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(decryptionFileLabel)
                    .addComponent(chooseDecryptionFileButton)
                    .addComponent(requestDecryptionFilePathLabel))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(parameterTitleLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(requestIncludeParametersButton)
                    .addComponent(requestExcludeParametersButton)
                    .addComponent(Request_Paramter_Ignore_select_noneButton))
                .addComponent(parameterInfoLabel)
                .addComponent(requestParameterTextField, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE)
                .addContainerGap()
        );

        return requestTypePane;
    }

    private JLayeredPane createResponseTypePane()
    {
        JLayeredPane responseTypePane = new JLayeredPane();
        responseTypePane.setBorder(new LineBorder(Color.GRAY, 1));

        JLabel label = new JLabel("Response Type");
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        label.setForeground(new Color(0xFF, 0x66, 0x33));
        response_completeBodyButton = new JRadioButton("Complete Body");
        response_parameterValueButton = new JRadioButton("Parameter Value");
        response_parameterKeyValueButton = new JRadioButton("Parameter Key and Value");
        response_noneButton = new JRadioButton("None");
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
                api.persistence().preferences().setString("pycript.response.type", selectedResponseType);
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
        encryptionDecryptionFileLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        encryptionDecryptionFileLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        JLabel encryptionFileLabel = new JLabel("Encryption File");
        JButton chooseEncryptionFileButton = new JButton("Choose File");
        responseEncryptionFilePathLabel = new JLabel("/usr/temp");

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
                        responseEncryptionFilePathLabel.setText(selectedResponseEncryptionFile);
                        api.persistence().preferences().setString("pycript.response.encryption.file", selectedResponseEncryptionFile);
                    }
                } else {

                    JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };
        chooseEncryptionFileButton.addActionListener(chooseEncryptionFileListener);

        JLabel decryptionFileLabel = new JLabel("Decryption File");
        JButton chooseDecryptionFileButton = new JButton("Choose File");
        responseDecryptionFilePathLabel = new JLabel("/usr/temp");

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
                        responseDecryptionFilePathLabel.setText(selectedResponseDecryptionFile);
                        api.persistence().preferences().setString("pycript.response.decryption.file", selectedResponseDecryptionFile);
                    }
                } else {

                    JOptionPane.showMessageDialog(null, "No file selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }
        };

        chooseDecryptionFileButton.addActionListener(chooseDecryptionFileListener);

        // Response Parameter Controls
        JLabel parameterTitleLabel = new JLabel("Parameters to Include/Exclude");
        parameterTitleLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        parameterTitleLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        responseIncludeParametersButton = new JRadioButton("Include");
        responseExcludeParametersButton = new JRadioButton("Exclude");
        Response_Paramter_Ignore_select_noneButton = new JRadioButton("None");
        Response_Paramter_Ignore_select_noneButton.setSelected(true);

        ButtonGroup parameterGroup = new ButtonGroup();
        parameterGroup.add(responseIncludeParametersButton);
        parameterGroup.add(responseExcludeParametersButton);
        parameterGroup.add(Response_Paramter_Ignore_select_noneButton);

        JLabel parameterInfoLabel = new JLabel("Separated by commas, case-sensitive:");
        responseParameterTextField = new JTextField("password,Current_Password");
        responseParameterTextField.setPreferredSize(new Dimension(200, 20));

        ActionListener responseParameterListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!response_parameterValueButton.isSelected() && !response_parameterKeyValueButton.isSelected()) {
                    Response_Paramter_Ignore_select_noneButton.setSelected(true);
                    JOptionPane.showMessageDialog(null, "Response Parameter Type must be selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                }
                api.persistence().preferences().setString("pycript.response.include.exclude", getResponseParameterIncludeExcludeType());
            }
        };

        responseIncludeParametersButton.addActionListener(responseParameterListener);
        responseExcludeParametersButton.addActionListener(responseParameterListener);
        Response_Paramter_Ignore_select_noneButton.addActionListener(e -> api.persistence().preferences().setString("pycript.response.include.exclude", "None"));
        responseParameterTextField.addActionListener(e -> api.persistence().preferences().setString("pycript.response.parameter.text", responseParameterTextField.getText()));

        responseTypePane.add(label, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_completeBodyButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_parameterValueButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_parameterKeyValueButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(response_noneButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(encryptionDecryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(encryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(chooseEncryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(responseEncryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(decryptionFileLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(chooseDecryptionFileButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(responseDecryptionFilePathLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(parameterTitleLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(responseIncludeParametersButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(responseExcludeParametersButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(Response_Paramter_Ignore_select_noneButton, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(parameterInfoLabel, JLayeredPane.DEFAULT_LAYER);
        responseTypePane.add(responseParameterTextField, JLayeredPane.DEFAULT_LAYER);

        GroupLayout layout = new GroupLayout(responseTypePane);
        responseTypePane.setLayout(layout);
        layout.setAutoCreateGaps(false);
        layout.setAutoCreateContainerGaps(false);

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
                            .addComponent(responseEncryptionFilePathLabel))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(decryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseDecryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(responseDecryptionFilePathLabel))
                        .addComponent(parameterTitleLabel)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(responseIncludeParametersButton)
                            .addComponent(responseExcludeParametersButton)
                            .addComponent(Response_Paramter_Ignore_select_noneButton))
                        .addComponent(parameterInfoLabel)
                        .addComponent(responseParameterTextField, GroupLayout.PREFERRED_SIZE, 150, GroupLayout.PREFERRED_SIZE))
                    .addContainerGap(5, Short.MAX_VALUE))
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
                    .addComponent(responseEncryptionFilePathLabel))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(decryptionFileLabel)
                    .addComponent(chooseDecryptionFileButton)
                    .addComponent(responseDecryptionFilePathLabel))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(parameterTitleLabel)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(responseIncludeParametersButton)
                    .addComponent(responseExcludeParametersButton)
                    .addComponent(Response_Paramter_Ignore_select_noneButton))
                .addComponent(parameterInfoLabel)
                .addComponent(responseParameterTextField, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE)
                .addContainerGap()
        );

        return responseTypePane;
    }

    private JLayeredPane createWebSocketPane()
    {
        JLayeredPane webSocketPane = new JLayeredPane();
        webSocketPane.setBorder(new LineBorder(Color.GRAY, 1));

        JLabel label = new JLabel("WebSocket Configuration");
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        label.setForeground(new Color(0xFF, 0x66, 0x33));

        webSocketStatusLabel = new JLabel("Status: OFF");
        webSocketStatusLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 11));
        webSocketStatusLabel.setForeground(Color.RED);

        webSocketToggleButton = new JButton("Turn ON");
        webSocketToggleButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (webSocketEncryptionFile != null && !webSocketEncryptionFile.isBlank() &&
                    webSocketDecryptionFile != null && !webSocketDecryptionFile.isBlank()) {

                    webSocketEnabled = !webSocketEnabled;

                    if (webSocketEnabled) {
                        webSocketToggleButton.setText("Turn OFF");
                        webSocketStatusLabel.setText("Status: ON");
                        webSocketStatusLabel.setForeground(new Color(0, 128, 0));
                    } else {
                        webSocketToggleButton.setText("Turn ON");
                        webSocketStatusLabel.setText("Status: OFF");
                        webSocketStatusLabel.setForeground(Color.RED);
                    }

                    api.persistence().preferences().setBoolean("pycript.websocket.enabled", webSocketEnabled);
                } else {
                    JOptionPane.showMessageDialog(null, "WebSocket Encryption and Decryption files are required", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        JLabel encryptionFileLabel = new JLabel("Encryption File");
        JButton chooseEncryptionFileButton = new JButton("Choose File");
        webSocketEncryptionFilePathLabel = new JLabel("No file selected");

        chooseEncryptionFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setDialogTitle("Select WebSocket Encryption File");

                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    webSocketEncryptionFile = selectedFile.getAbsolutePath();
                    webSocketEncryptionFilePathLabel.setText(webSocketEncryptionFile);
                    api.persistence().preferences().setString("pycript.websocket.encryption.file", webSocketEncryptionFile);
                }
            }
        });

        JLabel decryptionFileLabel = new JLabel("Decryption File");
        JButton chooseDecryptionFileButton = new JButton("Choose File");
        webSocketDecryptionFilePathLabel = new JLabel("No file selected");

        chooseDecryptionFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setDialogTitle("Select WebSocket Decryption File");

                int userSelection = fileChooser.showDialog(null, "Select");

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    webSocketDecryptionFile = selectedFile.getAbsolutePath();
                    webSocketDecryptionFilePathLabel.setText(webSocketDecryptionFile);
                    api.persistence().preferences().setString("pycript.websocket.decryption.file", webSocketDecryptionFile);
                }
            }
        });

        GroupLayout layout = new GroupLayout(webSocketPane);
        webSocketPane.setLayout(layout);
        layout.setAutoCreateGaps(false);
        layout.setAutoCreateContainerGaps(false);

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addComponent(label)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(webSocketStatusLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(webSocketToggleButton))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(encryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseEncryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(webSocketEncryptionFilePathLabel))
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(decryptionFileLabel)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(chooseDecryptionFileButton)
                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(webSocketDecryptionFilePathLabel)))
                    .addContainerGap(5, Short.MAX_VALUE))
        );

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(label)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(webSocketStatusLabel)
                    .addComponent(webSocketToggleButton))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(encryptionFileLabel)
                    .addComponent(chooseEncryptionFileButton)
                    .addComponent(webSocketEncryptionFilePathLabel))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(decryptionFileLabel)
                    .addComponent(chooseDecryptionFileButton)
                    .addComponent(webSocketDecryptionFilePathLabel))
                .addContainerGap()
        );

        return webSocketPane;
    }

    private JLayeredPane createAdditionalSettingsPane()
    {
        JLayeredPane additionalSettingsPane = new JLayeredPane();
        additionalSettingsPane.setBorder(new LineBorder(Color.GRAY, 1));

        JLabel additionalSettingsLabel = new JLabel("Additional Settings");
        additionalSettingsLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        additionalSettingsLabel.setForeground(new Color(0x00, 0x7A, 0xCC));
        JLabel languageLabel = new JLabel("Selected Language Binary");
        languageLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        languageLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        languageTextField = new JTextField(20);
        languageTextField.setText("usr/bin/python");
        languageTextField.addActionListener(e -> api.persistence().preferences().setString("pycript.language.path", languageTextField.getText()));
        JButton selectLanguageButton = new JButton("Select Language Binary Path");
        JButton clearLanguageButton = new JButton("Clear Language Selected");

        selectLanguageButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fileChooser.setDialogTitle("Select Language Binary");
            int userSelection = fileChooser.showDialog(null, "Select");
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                if (selectedFile != null) {
                    String filePath = selectedFile.getAbsolutePath();
                    languageTextField.setText(filePath);
                    api.persistence().preferences().setString("pycript.language.path", filePath);
                }
            }
        });

        clearLanguageButton.addActionListener(e -> {
            languageTextField.setText("");
            api.persistence().preferences().setString("pycript.language.path", "");
        });

        JLabel methodLabel = new JLabel("Encryption Decryption Method");
        methodLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        methodLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        requestmethodComboBox = new JComboBox<>(new String[]{"GET", "BODY", "BOTH"});
        requestmethodComboBox.addActionListener(e -> api.persistence().preferences().setString("pycript.request.method", (String) requestmethodComboBox.getSelectedItem()));

        JLabel forLabel = new JLabel("Encryption Decryption For");
        forLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        forLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        reqresponsecombobox = new JComboBox<>(new String[]{"Request", "Response", "BOTH"});
        reqresponsecombobox.addActionListener(e -> api.persistence().preferences().setString("pycript.reqresponse.combo", (String) reqresponsecombobox.getSelectedItem()));

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
        layout.setAutoCreateGaps(false);
        layout.setAutoCreateContainerGaps(false);

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
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(languageLabel)
                    .addComponent(languageTextField)
                    .addComponent(selectLanguageButton)
                    .addComponent(clearLanguageButton))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(methodLabel)
                    .addComponent(requestmethodComboBox))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(forLabel)
                    .addComponent(reqresponsecombobox))
                .addContainerGap()
        );

        return additionalSettingsPane;
    }

    private JLayeredPane createAutoEncryptPane()
    {
        JLayeredPane autoEncryptPane = new JLayeredPane();
        autoEncryptPane.setBorder(new LineBorder(Color.GRAY, 1));

        JLabel autoEncryptLabel = new JLabel("Auto Encrypt the Request");
        autoEncryptLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        autoEncryptLabel.setForeground(new Color(0xFF, 0x66, 0x33));
        currentStatusLabel = new JLabel("Current Status: OFF");
        turnOnButton = new JButton("Turn ON");
        turnOnButton.setEnabled(false);

        JLabel cannotTurnOnLabel = new JLabel("Cannot Turn ON Unless Request Type and Tool Type are selected");

        JLabel toolTypeLabel = new JLabel("Auto Encrypt Tool Type");
        toolTypeLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        toolTypeLabel.setForeground(new Color(0xFF, 0x66, 0x33));
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
                        selectedToolTypes.clear();
                        turnOnButton.setEnabled(false);
                        scannerCheckBox.setSelected(false);
                        repeaterCheckBox.setSelected(false);
                        proxyCheckBox.setSelected(false);
                        extenderCheckBox.setSelected(false);
                        intruderCheckBox.setSelected(false);
                        currentStatusLabel.setText("Current Status: OFF");
                        turnOnButton.setText("Turn ON");
                    } else {
                        selectedToolTypes.clear();
                        StringBuilder selectedTools = new StringBuilder();
                        if (scannerCheckBox.isSelected()) {
                            selectedTools.append("Scanner, ");
                            selectedToolTypes.add(ToolType.SCANNER);
                        }
                        if (repeaterCheckBox.isSelected()) {
                            selectedTools.append("Repeater, ");
                            selectedToolTypes.add(ToolType.REPEATER);
                        }
                        if (proxyCheckBox.isSelected()) {
                            selectedTools.append("Proxy, ");
                            selectedToolTypes.add(ToolType.PROXY);
                        }
                        if (extenderCheckBox.isSelected()) {
                            selectedTools.append("Extender, ");
                            selectedToolTypes.add(ToolType.EXTENSIONS);
                        }
                        if (intruderCheckBox.isSelected()) {
                            selectedTools.append("Intruder, ");
                            selectedToolTypes.add(ToolType.INTRUDER);
                        }


                        selectedToolType = selectedTools.substring(0, selectedTools.length() - 2);

                        turnOnButton.setEnabled(true);
                    }
                } else {

                    selectedToolType = "";
                    selectedToolTypes.clear();
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
                        turnOnButton.setBackground(new Color(0, 163, 16));
                        turnOnButton.setForeground(Color.WHITE);
                        // Register HTTP handler
                        if (httpHandlerRegistration == null) {
                            httpHandlerRegistration = api.http().registerHttpHandler(new AutoEncryptHttpHandler(api, selectedToolTypes));
                        }
                    } else {
                        currentStatusLabel.setText("Current Status: OFF");
                        turnOnButton.setText("Turn ON");
                        turnOnButton.setBackground(new Color(255, 21, 0));
                        turnOnButton.setForeground(Color.WHITE);
                        // Unregister HTTP handler
                        if (httpHandlerRegistration != null) {
                            httpHandlerRegistration.deregister();
                            httpHandlerRegistration = null;
                        }
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
        layout.setAutoCreateGaps(false);
        layout.setAutoCreateContainerGaps(false);

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
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(turnOnButton)
                    .addComponent(currentStatusLabel))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(cannotTurnOnLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(toolTypeLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(scannerCheckBox)
                    .addComponent(repeaterCheckBox)
                    .addComponent(intruderCheckBox))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(proxyCheckBox)
                    .addComponent(extenderCheckBox))
                .addContainerGap()
        );

        return autoEncryptPane;
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

    public static String getResponseParameterIncludeExcludeType() {
        ConfigTab instance = getInstance();
        if (instance != null) {
            if (instance.responseIncludeParametersButton != null && instance.responseIncludeParametersButton.isSelected()) {
                return "Include Parameters";
            } else if (instance.responseExcludeParametersButton != null && instance.responseExcludeParametersButton.isSelected()) {
                return "Exclude Parameters";
            }
        }
        return "None";
    }

    public static List<String> getResponseParameterList() {
        List<String> paramList = new ArrayList<>();
        ConfigTab instance = getInstance();
        if (instance != null && instance.responseParameterTextField != null) {
            String paramText = instance.responseParameterTextField.getText();
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

    private static ConfigTab configTabInstance;

    private static ConfigTab getInstance() {
        return configTabInstance;
    }

    public static void setInstance(ConfigTab instance) {
        configTabInstance = instance;
    }

    private void loadSettings() {
        try {
            String requestType = api.persistence().preferences().getString("pycript.request.type");
            if (requestType != null && !requestType.isEmpty()) {
                selectedRequestType = requestType;
                if ("Complete Body".equals(requestType) && request_noneButton != null) {
                    request_noneButton.setSelected(true);
                } else if ("Parameter Value".equals(requestType) && request_parameterValueButton != null) {
                    request_parameterValueButton.setSelected(true);
                } else if ("Parameter Key and Value".equals(requestType) && request_parameterKeyValueButton != null) {
                    request_parameterKeyValueButton.setSelected(true);
                }
            }

            String responseType = api.persistence().preferences().getString("pycript.response.type");
            if (responseType != null && !responseType.isEmpty()) {
                selectedResponseType = responseType;
                if ("Parameter Value".equals(responseType) && response_parameterValueButton != null) {
                    response_parameterValueButton.setSelected(true);
                } else if ("Parameter Key and Value".equals(responseType) && response_parameterKeyValueButton != null) {
                    response_parameterKeyValueButton.setSelected(true);
                }
            }

            String reqEncFile = api.persistence().preferences().getString("pycript.request.encryption.file");
            if (reqEncFile != null && !reqEncFile.isEmpty()) {
                selectedRequestEncryptionFile = reqEncFile;
                if (requestEncryptionFilePathLabel != null) {
                    requestEncryptionFilePathLabel.setText(reqEncFile);
                }
            }

            String reqDecFile = api.persistence().preferences().getString("pycript.request.decryption.file");
            if (reqDecFile != null && !reqDecFile.isEmpty()) {
                selectedRequestDecryptionFile = reqDecFile;
                if (requestDecryptionFilePathLabel != null) {
                    requestDecryptionFilePathLabel.setText(reqDecFile);
                }
            }

            String resEncFile = api.persistence().preferences().getString("pycript.response.encryption.file");
            if (resEncFile != null && !resEncFile.isEmpty()) {
                selectedResponseEncryptionFile = resEncFile;
                if (responseEncryptionFilePathLabel != null) {
                    responseEncryptionFilePathLabel.setText(resEncFile);
                }
            }

            String resDecFile = api.persistence().preferences().getString("pycript.response.decryption.file");
            if (resDecFile != null && !resDecFile.isEmpty()) {
                selectedResponseDecryptionFile = resDecFile;
                if (responseDecryptionFilePathLabel != null) {
                    responseDecryptionFilePathLabel.setText(resDecFile);
                }
            }

            String langPath = api.persistence().preferences().getString("pycript.language.path");
            if (langPath != null && !langPath.isEmpty() && languageTextField != null) {
                languageTextField.setText(langPath);
            }

            String reqMethod = api.persistence().preferences().getString("pycript.request.method");
            if (reqMethod != null && !reqMethod.isEmpty() && requestmethodComboBox != null) {
                requestmethodComboBox.setSelectedItem(reqMethod);
            }

            String reqRespCombo = api.persistence().preferences().getString("pycript.reqresponse.combo");
            if (reqRespCombo != null && !reqRespCombo.isEmpty() && reqresponsecombobox != null) {
                reqresponsecombobox.setSelectedItem(reqRespCombo);
            }

            String reqParamText = api.persistence().preferences().getString("pycript.request.parameter.text");
            if (reqParamText != null && !reqParamText.isEmpty() && requestParameterTextField != null) {
                requestParameterTextField.setText(reqParamText);
            }

            String resParamText = api.persistence().preferences().getString("pycript.response.parameter.text");
            if (resParamText != null && !resParamText.isEmpty() && responseParameterTextField != null) {
                responseParameterTextField.setText(resParamText);
            }

            String reqIncExc = api.persistence().preferences().getString("pycript.request.include.exclude");
            if (reqIncExc != null && !reqIncExc.isEmpty()) {
                if ("Include Parameters".equals(reqIncExc) && requestIncludeParametersButton != null) {
                    requestIncludeParametersButton.setSelected(true);
                } else if ("Exclude Parameters".equals(reqIncExc) && requestExcludeParametersButton != null) {
                    requestExcludeParametersButton.setSelected(true);
                } else if (Request_Paramter_Ignore_select_noneButton != null) {
                    Request_Paramter_Ignore_select_noneButton.setSelected(true);
                }
            }

            String resIncExc = api.persistence().preferences().getString("pycript.response.include.exclude");
            if (resIncExc != null && !resIncExc.isEmpty()) {
                if ("Include Parameters".equals(resIncExc) && responseIncludeParametersButton != null) {
                    responseIncludeParametersButton.setSelected(true);
                } else if ("Exclude Parameters".equals(resIncExc) && responseExcludeParametersButton != null) {
                    responseExcludeParametersButton.setSelected(true);
                } else if (Response_Paramter_Ignore_select_noneButton != null) {
                    Response_Paramter_Ignore_select_noneButton.setSelected(true);
                }
            }

            String wsEncFile = api.persistence().preferences().getString("pycript.websocket.encryption.file");
            if (wsEncFile != null && !wsEncFile.isEmpty()) {
                webSocketEncryptionFile = wsEncFile;
                if (webSocketEncryptionFilePathLabel != null) {
                    webSocketEncryptionFilePathLabel.setText(wsEncFile);
                }
            }

            String wsDecFile = api.persistence().preferences().getString("pycript.websocket.decryption.file");
            if (wsDecFile != null && !wsDecFile.isEmpty()) {
                webSocketDecryptionFile = wsDecFile;
                if (webSocketDecryptionFilePathLabel != null) {
                    webSocketDecryptionFilePathLabel.setText(wsDecFile);
                }
            }

            Boolean wsEnabled = api.persistence().preferences().getBoolean("pycript.websocket.enabled");
            if (wsEnabled != null) {
                webSocketEnabled = wsEnabled;
                if (webSocketToggleButton != null && webSocketStatusLabel != null) {
                    if (webSocketEnabled) {
                        webSocketToggleButton.setText("Turn OFF");
                        webSocketStatusLabel.setText("Status: ON");
                        webSocketStatusLabel.setForeground(new Color(0, 128, 0));
                    } else {
                        webSocketToggleButton.setText("Turn ON");
                        webSocketStatusLabel.setText("Status: OFF");
                        webSocketStatusLabel.setForeground(Color.RED);
                    }
                }
            }
        } catch (Exception e) {

        }
    }

}