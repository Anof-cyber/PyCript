from burp import (IBurpExtender, ITab,IMessageEditorTabFactory,IMessageEditorTab,IContextMenuFactory, IContextMenuInvocation,IMessageEditorController,IHttpListener)
from java.awt import (BorderLayout,Font,Color)
from javax.swing import (JTabbedPane,JPanel ,JRadioButton,ButtonGroup,JRadioButton,JLabel,
JSeparator,JButton,JToggleButton,JCheckBox,JScrollPane,GroupLayout,LayoutStyle,JFileChooser,JMenuItem,JOptionPane,JTable,JSplitPane,JPopupMenu,SwingConstants)
from javax.swing.table import AbstractTableModel;
from javax.swing.filechooser import FileNameExtensionFilter
from java.lang import Short
import sys
from java import io
from threading import Thread,Lock

sys.path.append("Resource/rsyntaxtextarea-3.3.1.jar")

from org.fife.ui.rsyntaxtextarea import RSyntaxTextArea,SyntaxConstants,Theme
from org.fife.ui.rtextarea import RTextArea,RTextScrollPane
from pycript.Requesttab import CriptInputTab
from pycript.Reqcheck import Requestchecker,DecryptRequest,EncryptRequest



class BurpExtender(IBurpExtender, ITab,IMessageEditorTabFactory,IContextMenuFactory, IMessageEditorController, AbstractTableModel,IHttpListener):


    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.tooltypelist = []
        
        

        # Allowing debugging
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Informing Burp suite the name of the extension
        callbacks.setExtensionName("PyCript")
        callbacks.printOutput("Author: Sourav Kalal")
        callbacks.printOutput("Version: 0.1")
        callbacks.printOutput("https://github.com/Anof-cyber/PyCript")
        callbacks.printOutput("https://pycript.souravkalal.tech/")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)
        



        self.selectedrequesttpye = None
        self.tab = JPanel()
        self.tabbedPane = JTabbedPane()
        self.tab.add("Center", self.tabbedPane) 

        self.firstTab = JPanel()
        self.firstTab.layout = BorderLayout()
        #self.firstTab.layout = BorderLayout()
        self.tabbedPane.addTab("Config", self.firstTab)

        self.secondTab = JPanel()
        self.secondTab.layout = BorderLayout()
        #self.firstTab.layout = BorderLayout()
        self.tabbedPane.addTab("Decrypted Request", self.secondTab)

        
        self._log = list()
        self._lock = Lock()
        
        

        popupMenu = JPopupMenu()
        sendscannerItem = JMenuItem("Send to Active Scanner", actionPerformed=self.sendtoscanner)
        sendRepeaterItem = JMenuItem("Send to Repeater", actionPerformed=self.sendtorepeater)
        sendIntruderItem = JMenuItem("Send to Intruder", actionPerformed=self.sendtointruder)
        repeatrequest = JMenuItem("Resend HTTP Request", actionPerformed=self.resendrequest)
        popupMenu.add(sendscannerItem)
        popupMenu.add(sendRepeaterItem)
        popupMenu.add(sendIntruderItem)
        popupMenu.add(repeatrequest)

        
        self.logTable = Table(self)
        self.logTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.logTable.getTableHeader().setReorderingAllowed(False)
        self.logTable.getColumnModel().getColumn(0).setPreferredWidth(30)
        
        self.logTable.getColumnModel().getColumn(1).setPreferredWidth(600)
        self.logTable.getColumnModel().getColumn(2).setPreferredWidth(80)
       
        self.logTable.setRowSelectionAllowed(True)
        self.scrollPane2 = JScrollPane(self.logTable)
        self.logTable.setComponentPopupMenu(popupMenu)
        self.scrollPane2.getViewport().setView((self.logTable))

        self.requestViewer = callbacks.createMessageEditor(self, True)
        self.responseViewer = callbacks.createMessageEditor(self, True)
        self.editor_view = JTabbedPane()
        self.editor_view.addTab("Request", self.requestViewer.getComponent())
        self.editor_view.addTab("Response", self.responseViewer.getComponent())
        spl = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        spl.setLeftComponent(self.scrollPane2)
        spl.setRightComponent(self.editor_view)
        self.secondTab.add(spl)
        
        self.callbacks.customizeUiComponent(spl)
        self.callbacks.customizeUiComponent(self.logTable)
        self.callbacks.customizeUiComponent(self.scrollPane2)
        self.callbacks.customizeUiComponent(self.editor_view)

    



        callbacks.addSuiteTab(self)

        self.decryptionfilepath = None
        self.encryptionfilepath = None

        self.RequestTypeRadioGroup = ButtonGroup();
        self.Wholebodyjsonradio = JRadioButton();
        self.Requestypelabel = JLabel();
        self.JsonValueradio = JRadioButton();
        self.JsonkeyValueradio = JRadioButton();
        self.CustomBodyRadio = JRadioButton();
        self.CustomRequestRadio = JRadioButton();
        self.RequestTypeNoneRadio = JRadioButton();
        self.jSeparator1 = JSeparator();
        self.Encryptionfilelabel = JLabel();
        self.FileChooserLabel = JLabel();
        self.Encryptionfilechooserbutton = JButton();
        self.Decryptionfilelabel = JLabel();
        self.Decryptionfilechooserbutton = JButton();
        self.FileChooserErrorlabel = JLabel();
        self.AutoEncryptLabel = JLabel();
        self.Autoencryptonoffbutton = JToggleButton();
        self.Autoencryptonoffbutton.setEnabled(False)

        self.AutoencryptTogglestatuslabel = JLabel();
        self.FileChooserErrorlabel1 = JLabel();
        self.jSeparator4 = JSeparator();
        self.AutoencryptTooltypeScanner = JCheckBox();
        self.AutoencryptTooltypeScanner.addActionListener(self.encrypttoollistener)

        self.AutoEncryptLabel1 = JLabel();
        self.AutoencryptTooltypeExtender = JCheckBox();
        self.AutoencryptTooltypeExtender.addActionListener(self.encrypttoollistener)

        self.AutoencryptTooltypeRepeater = JCheckBox();
        self.AutoencryptTooltypeRepeater.addActionListener(self.encrypttoollistener)


        self.AutoencryptTooltypeProxy = JCheckBox();
        self.AutoencryptTooltypeProxy.addActionListener(self.encrypttoollistener)

        self.AutoencryptTooltypeIntruder = JCheckBox();
        self.AutoencryptTooltypeIntruder.addActionListener(self.encrypttoollistener)

        self.AutoEncrypttooltypeerrorlabel = JLabel();
        self.Encryptioncodelabel = JLabel();
        self.Decryptioncodelabel = JLabel();
        #self.jScrollPane1 = JScrollPane();
        #self.EncryptioncodeEditorPane = JEditorPane();
        self.EncryptioncodeEditorPane = RSyntaxTextArea()
        self.EncryptioncodeEditorPane.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT)
        
        self.EncryptioncodeEditorPane.setCodeFoldingEnabled(True);
        self.EncryptioncodeEditorPane.setAutoIndentEnabled(True)
        self.EncryptioncodeEditorPane.setEditable(False)
        self.jScrollPane1 = RTextScrollPane(self.EncryptioncodeEditorPane)

        with open("Resource/dark.xml", "r") as file:
            theme_xml = file.read()
            file.close()

        input_stream = io.StringBufferInputStream(theme_xml)
        theme = Theme.load(input_stream) 
        theme.apply(self.EncryptioncodeEditorPane)   
     


        #self.jScrollPane2 = JScrollPane();
        self.DecryptioncodeEditorPane = RSyntaxTextArea();
        self.DecryptioncodeEditorPane.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT)
        self.DecryptioncodeEditorPane.setCodeFoldingEnabled(True);
        self.DecryptioncodeEditorPane.setAutoIndentEnabled(True)
        self.DecryptioncodeEditorPane.setEditable(False)
        self.jScrollPane2 = RTextScrollPane(self.DecryptioncodeEditorPane)
        theme.apply(self.DecryptioncodeEditorPane)  

        self.RequestTypeRadioGroup.add(self.Wholebodyjsonradio);
        self.Wholebodyjsonradio.setText("Whole Body (JSON)");
        self.Wholebodyjsonradio.addActionListener(self.requestypelistner)

        self.Requestypelabel.setFont(Font("Segoe UI", 1, 14))
        self.Requestypelabel.setText("Request Type");

        self.RequestTypeRadioGroup.add(self.JsonValueradio);
        self.JsonValueradio.setText("JSON Value");
        self.JsonValueradio.addActionListener(self.requestypelistner)
        
        self.RequestTypeRadioGroup.add(self.JsonkeyValueradio);
        self.JsonkeyValueradio.setText("JSON Key & Value");
        self.JsonkeyValueradio.addActionListener(self.requestypelistner)

        self.RequestTypeRadioGroup.add(self.CustomBodyRadio);
        self.CustomBodyRadio.setText("Custom Body");
        self.CustomBodyRadio.addActionListener(self.requestypelistner)

        self.RequestTypeRadioGroup.add(self.CustomRequestRadio);
        self.CustomRequestRadio.setText("Custom Request");
        self.CustomRequestRadio.addActionListener(self.requestypelistner)

        self.RequestTypeRadioGroup.add(self.RequestTypeNoneRadio);
        self.RequestTypeNoneRadio.setText("None");
        self.RequestTypeNoneRadio.addActionListener(self.requestypelistner)
        self.RequestTypeNoneRadio.setSelected(True)

        self.Encryptionfilelabel.setText("Encryption Javascript File");
        self.Encryptionfilechooserbutton.addActionListener(self.importencryptionjsfile)



        self.FileChooserLabel.setFont(Font("Segoe UI", 1, 14));
        self.FileChooserLabel.setText("Encryption Deryption Files");

        self.Encryptionfilechooserbutton.setText("Choose JS File");
        

        self.Decryptionfilelabel.setText("Decryption Javascript File");
        self.Decryptionfilechooserbutton.addActionListener(self.importdecryptionjsfile)

        self.Decryptionfilechooserbutton.setText("Choose JS File");
        

        self.FileChooserErrorlabel.setForeground(Color(237, 121, 5));
        self.FileChooserErrorlabel.setFont(Font("Segoe UI", 1, 14));
        #self.FileChooserErrorlabel.setText("Invalid File Selected");

        self.AutoEncryptLabel.setFont(Font("Segoe UI", 1, 14));
        self.AutoEncryptLabel.setText("Auto Encrypt The Request (Request Type should be selected)");

        self.Autoencryptonoffbutton.setText("Turn On");
        self.Autoencryptonoffbutton.setBackground(Color(255, 21, 0))
        self.Autoencryptonoffbutton.setForeground(Color(255, 255, 255));
        self.Autoencryptonoffbutton.setFont(Font("Segoe UI", 1, 15));
        self.Autoencryptonoffbutton.setToolTipText("");
        self.Autoencryptonoffbutton.addItemListener(self.Autoencryptstatuslistner)

        self.AutoencryptTogglestatuslabel.setText("Current Status: OFF");

        self.FileChooserErrorlabel1.setForeground(Color(237, 121, 5));
        self.FileChooserErrorlabel1.setText("Cannot Turn On Unless Request Type is not selected");

        #self.AutoencryptTooltypeScanner.setSelected(True);
        self.AutoencryptTooltypeScanner.setText("Scanner");
        


        self.AutoEncryptLabel1.setFont(Font("Segoe UI", 1, 14))
        self.AutoEncryptLabel1.setText("Auto Encrypt Tool Type");

        self.AutoencryptTooltypeExtender.setText("Extender");
        

        self.AutoencryptTooltypeRepeater.setText("Repeater");
       

        self.AutoencryptTooltypeProxy.setText("Proxy");
        

        self.AutoencryptTooltypeIntruder.setText("Intruder");
        

        self.AutoEncrypttooltypeerrorlabel.setForeground(Color(237, 121, 5));
        self.AutoEncrypttooltypeerrorlabel.setText("At Least One should be selected to turn on Auto Encrypt");

        self.Encryptioncodelabel.setFont(Font("Segoe UI", 1, 12)); 
        self.Encryptioncodelabel.setText("Encryption Code");

        self.Decryptioncodelabel.setFont(Font("Segoe UI", 1, 12)); 
        self.Decryptioncodelabel.setText("Decryption Code");

        #self.EncryptioncodeEditorPane.setContentType("text/javascript");
        #self.jScrollPane1.setViewportView(self.EncryptioncodeEditorPane);
        #self.EncryptioncodeEditorPane.getAccessibleContext().setAccessibleDescription("text/javascript");
        #self.EncryptioncodeEditorPane.setText("Hellowlr");
        #self.EncryptioncodeEditorPane.setEditable(False);

        #self.DecryptioncodeEditorPane.setContentType("text/javascript");
        #self.jScrollPane2.setViewportView(self.DecryptioncodeEditorPane);
        #self.DecryptioncodeEditorPane.setEditable(False);
        #self.DecryptioncodeEditorPane.getAccessibleContext().setAccessibleDescription("text/javascript");
       
        layout = GroupLayout(self.firstTab);
        self.firstTab.setLayout(layout);
        layout.linkSize(SwingConstants.VERTICAL, [self.jScrollPane1, self.jScrollPane2]);
        layout.linkSize(SwingConstants.VERTICAL, [self.Decryptioncodelabel, self.Encryptioncodelabel]);
        layout.linkSize(SwingConstants.HORIZONTAL, [self.jScrollPane1, self.jScrollPane2]);
        layout.linkSize(SwingConstants.HORIZONTAL, [self.Decryptioncodelabel, self.Encryptioncodelabel]);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(self.jSeparator4)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(self.AutoEncryptLabel)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 450, GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(self.jScrollPane2, GroupLayout.PREFERRED_SIZE, 450, GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(225, 225, 225)
                                .addComponent(self.FileChooserErrorlabel))
                            .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(self.Autoencryptonoffbutton)
                                        .addGap(18, 18, 18)
                                        .addComponent(self.AutoencryptTogglestatuslabel))
                                    .addComponent(self.FileChooserErrorlabel1)
                                    .addComponent(self.AutoEncryptLabel1)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(self.AutoencryptTooltypeScanner)
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(self.AutoencryptTooltypeExtender)
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(self.AutoencryptTooltypeRepeater)
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(self.AutoencryptTooltypeProxy)
                                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(self.AutoencryptTooltypeIntruder))
                                    .addComponent(self.AutoEncrypttooltypeerrorlabel)
                                    .addComponent(self.FileChooserLabel)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addGroup(layout.createSequentialGroup()
                                            .addGap(195, 195, 195)
                                                .addComponent(self.Encryptionfilelabel)
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                .addComponent(self.Encryptionfilechooserbutton)
                                                .addGap(35, 35, 35)
                                                .addComponent(self.Decryptionfilelabel))
                                                .addGap(35, 35, 35)
                                                .addGap(65, 65, 65)
                                            .addGroup(layout.createSequentialGroup()
                                                .addGap(94, 94, 94)
                                                .addComponent(self.Encryptioncodelabel)))
                                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addGroup(layout.createSequentialGroup()
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                                .addComponent(self.Decryptionfilechooserbutton))
                                            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                            .addGap(94, 94, 94)
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(self.Decryptioncodelabel)
                                                )))))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addComponent(self.Requestypelabel))
                            .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(self.Wholebodyjsonradio)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.JsonValueradio)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.JsonkeyValueradio)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.CustomBodyRadio)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.CustomRequestRadio)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.RequestTypeNoneRadio))
                            .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(self.jSeparator1)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(self.Requestypelabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.Wholebodyjsonradio)
                    .addComponent(self.JsonValueradio)
                    .addComponent(self.JsonkeyValueradio)
                    .addComponent(self.CustomBodyRadio)
                    .addComponent(self.CustomRequestRadio)
                    .addComponent(self.RequestTypeNoneRadio))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.jSeparator1, GroupLayout.PREFERRED_SIZE, 10, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.AutoEncryptLabel)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.Autoencryptonoffbutton)
                    .addComponent(self.AutoencryptTogglestatuslabel))
                .addGap(11, 11, 11)
                .addComponent(self.FileChooserErrorlabel1)
                .addGap(18, 18, 18)
                .addComponent(self.AutoEncryptLabel1)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.AutoencryptTooltypeScanner)
                    .addComponent(self.AutoencryptTooltypeExtender)
                    .addComponent(self.AutoencryptTooltypeRepeater)
                    .addComponent(self.AutoencryptTooltypeProxy)
                    .addComponent(self.AutoencryptTooltypeIntruder))
                .addGap(5, 5, 5)
                .addComponent(self.AutoEncrypttooltypeerrorlabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(self.jSeparator4, GroupLayout.PREFERRED_SIZE, 10, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.FileChooserLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.Encryptionfilelabel)
                    .addComponent(self.Encryptionfilechooserbutton)
                    .addGap(18, 18, 18)
                    .addComponent(self.Decryptionfilelabel)
                    .addGap(18, 18, 18)
                    .addComponent(self.Decryptionfilechooserbutton))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.FileChooserErrorlabel)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.Encryptioncodelabel)
                    .addComponent(self.Decryptioncodelabel))
                    
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.jScrollPane2, GroupLayout.PREFERRED_SIZE, 300, GroupLayout.PREFERRED_SIZE))
                .addGap(16, 16, 16))


                
        )
    
    # Listeners for Request type radio buttons
    def requestypelistner(self, e):
        selected = e.getSource()
        if not selected.getText() == "None":

            if None not in (self.decryptionfilepath,self.encryptionfilepath):
                self.FileChooserErrorlabel.setText("");
                #self.Autoencryptonoffbutton.setEnabled(True)
                self.RequestTypeNoneRadio.setSelected(False)
                self.selectedrequesttpye = selected.getText()
                if self.AutoencryptTooltypeScanner.isSelected() or self.AutoencryptTooltypeExtender.isSelected() or self.AutoencryptTooltypeRepeater.isSelected() or self.AutoencryptTooltypeProxy.isSelected() or self.AutoencryptTooltypeIntruder.isSelected() == True:
                    self.Autoencryptonoffbutton.setEnabled(True)
            else:
                self.FileChooserErrorlabel.setText("Encryption and Decryption File Required to Start");
                self.RequestTypeNoneRadio.setSelected(True)
                self.Autoencryptonoffbutton.setEnabled(False)
                self.Autoencryptonoffbutton.setSelected(False)
                self.selectedrequesttpye = "None"
        elif selected.getText() == "None":
            self.selectedrequesttpye = "None"
            self.Autoencryptonoffbutton.setEnabled(False)
            self.Autoencryptonoffbutton.setSelected(False)



    # Handles Import for the Encryption File
    def importencryptionjsfile(self,e):
        chooseFile = JFileChooser()
        filter = FileNameExtensionFilter("js files", ["js"])
        chooseFile.addChoosableFileFilter(filter)    
        ret = chooseFile.showDialog(self.tab, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            fileLoad = chooseFile.getSelectedFile()
            self.encryptionfilepath = fileLoad.getAbsolutePath()
            file = open(self.encryptionfilepath,mode='r')
            self.encryptioncode = file.read()
            self.EncryptioncodeEditorPane.setText(self.encryptioncode)
            file.close()


    # Handle Import for Decryption File
    def importdecryptionjsfile(self,e):
        chooseFile = JFileChooser()
        filter = FileNameExtensionFilter("js files", ["js"])
        chooseFile.addChoosableFileFilter(filter)    
        ret = chooseFile.showDialog(self.tab, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            fileLoad = chooseFile.getSelectedFile()
            self.decryptionfilepath = fileLoad.getAbsolutePath()
            file = open(self.decryptionfilepath,mode='r')
            self.encryptioncode = file.read()
            self.DecryptioncodeEditorPane.setText(self.encryptioncode)
            file.close()



    # Returning the Extension Tab name to burp
    def getTabCaption(self):
        return "PyCript"


    # Returning the UI to the extension tab - Returning the new taB insite the extension tab
    def getUiComponent(self):
        return self.tabbedPane    


    # Creating the tab for Request/Response to view Decrypted Request body
    def createNewInstance(self, controller, editable):
        
        # create a new instance of our custom editor tab
        return CriptInputTab(self, controller, editable)   



    # Auto Encrypt the request and modify the request
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            toolname = self.callbacks.getToolName(toolFlag)
           
            if toolname in self.tooltypelist:

                request = self.helpers.analyzeRequest(messageInfo)
                bodyoffset = request.getBodyOffset()
                self.header = request.getHeaders()
                self.stringrequest = self.helpers.bytesToString(messageInfo.getRequest())
                self.body = self.stringrequest[bodyoffset:len(self.stringrequest)]

                
                messageInfo.setRequest(EncryptRequest(self,self.body,self.header))


    # Listener for Auto Encrpyt the request 
    def Autoencryptstatuslistner(self,e):

        self.Autoencryptonoffbutton = e.getItem()
        if self.Autoencryptonoffbutton.isSelected():
                self.Autoencryptonoffbutton.setText("Turn OFF");
                self.Autoencryptonoffbutton.setBackground(Color(0, 163, 16))
                self.Autoencryptonoffbutton.setForeground(Color(255, 255, 255));
                self.AutoencryptTogglestatuslabel.setText("Current Status: ON")
                self.callbacks.registerHttpListener(self)
        else:
            self.Autoencryptonoffbutton.setText("Turn On");
            self.Autoencryptonoffbutton.setBackground(Color(255, 21, 0))
            self.Autoencryptonoffbutton.setForeground(Color(255, 255, 255));
            self.AutoencryptTogglestatuslabel.setText("Current Status: OFF")
            self.callbacks.removeHttpListener(self)


    # Listener for Tool Type Selected
    def encrypttoollistener(self,e):        
        
        if self.AutoencryptTooltypeScanner.isSelected() or self.AutoencryptTooltypeExtender.isSelected() or self.AutoencryptTooltypeRepeater.isSelected() or self.AutoencryptTooltypeProxy.isSelected() or self.AutoencryptTooltypeIntruder.isSelected() == True:
            
            if self.RequestTypeNoneRadio.isSelected():
                self.Autoencryptonoffbutton.setEnabled(False)
                self.Autoencryptonoffbutton.setSelected(False)
            else:
                self.Autoencryptonoffbutton.setEnabled(True)
                self.tooltypelist = []
                if self.AutoencryptTooltypeScanner.isSelected():
                    self.tooltypelist.append("Scanner")
                if self.AutoencryptTooltypeExtender.isSelected():
                    self.tooltypelist.append("Extender")
                if self.AutoencryptTooltypeRepeater.isSelected():
                    self.tooltypelist.append("Repeater")
                if self.AutoencryptTooltypeProxy.isSelected():
                    self.tooltypelist.append("Proxy")
                if self.AutoencryptTooltypeIntruder.isSelected():
                    self.tooltypelist.append("Intruder")
                


        else:
            self.Autoencryptonoffbutton.setEnabled(False)
            self.Autoencryptonoffbutton.setSelected(False)
        

    # Create the Menu for the extension
    def createMenuItems(self,invocation):
        menu_list = []

        menu_list.append(JMenuItem("Decrypt String", None,actionPerformed=lambda x, inv=invocation: self.decryptstring(inv)))
        menu_list.append(JMenuItem("Encrypt String", None,actionPerformed=lambda x, inv=invocation: self.encryptstring(inv)))
        #menu_list.append(JMenuItem("Decrypt Request", None,actionPerformed=lambda x, inv=invocation: self.decryptrequest(inv)))
        menu_list.append(JMenuItem("Decrypt Request", None,actionPerformed=lambda x, inv=invocation: Thread(target=self.decryptrequest, args=(inv,)).start()))

       
      
        return menu_list


    # Decrypt the selected Request from Menu and Store the Decrypted Request in the Decrypted Request Table
    def decryptrequest(self,invocation):
        if not str(self.selectedrequesttpye) == "None":
            reqRes = invocation.getSelectedMessages()
            for items in reqRes:
                
                req = self.helpers.analyzeRequest(items)
                self.method = req.getMethod()
                self.url = items.getUrl()
                
                gettingrequest = items.getRequest()
                self.requestinst = self.helpers.bytesToString(gettingrequest)
                self.responseinbytes = items.getResponse()
                self.responseinst = self.helpers.bytesToString(self.responseinbytes)
                getody = req.getBodyOffset()
                self.body = self.requestinst[getody:len(self.requestinst)]
                self.header = req.getHeaders()

                self.decryptedrequest = DecryptRequest(self,self.body,self.header)
                rowss = self.logTable.getRowCount()
                self.sr2 = str((rowss + 1))
                httpservice = items.getHttpService()
               

                self._lock.acquire()
                row = len(self._log)
               
                self._log.append(LogEntry(self.sr2,self.url, self.method,self.decryptedrequest, self.responseinst,httpservice))
               
                self.fireTableRowsInserted(row, row)
                self._lock.release()



    # Show the Encrypted String
    def encryptstring(self,invocation):
        if not str(self.selectedrequesttpye) == "None":
            http_request_response = invocation.getSelectedMessages()[0]
            context = invocation.getInvocationContext()
            self.selection = invocation.getSelectionBounds()
            if (context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or
                    context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                ):
                self.selectedrequst = True
                message_bytes = http_request_response.getRequest()
            else:
                self.selectedrequst = False
                message_bytes = http_request_response.getResponse()

            text = self.helpers.bytesToString(message_bytes)
            query = text[self.selection[0]:self.selection[1]]
            output = Requestchecker(self,query,http_request_response)
            encryptedstring = output.encryptstring()
            
        
        
            inputText = JOptionPane.showInputDialog(None, "Encrypted String", "Encrpytion", JOptionPane.PLAIN_MESSAGE, None, None, str(encryptedstring))
        
        else:
            inputText = JOptionPane.showInputDialog(None, "Encrypted String", "Encrpytion", JOptionPane.PLAIN_MESSAGE, None, None, str("Request Type is not selected"))
        


    # Show Decrypted string Popup 
    def decryptstring(self,invocation):

        if not str(self.selectedrequesttpye) == "None":
            http_request_response = invocation.getSelectedMessages()[0]
            context = invocation.getInvocationContext()
            self.selection = invocation.getSelectionBounds()
            if (context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or
                    context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                ):
                self.selectedrequst = True
                message_bytes = http_request_response.getRequest()
            else:
                self.selectedrequst = False
                message_bytes = http_request_response.getResponse()

            text = self.helpers.bytesToString(message_bytes)
            query = text[self.selection[0]:self.selection[1]]
            output = Requestchecker(self,query,http_request_response)
            decryptedstring = output.decryptstring()
           
        
        
            inputText = JOptionPane.showInputDialog(None, "Decrypted String", "Encrpytion", JOptionPane.PLAIN_MESSAGE, None, None, str(decryptedstring))
        
        else:
            inputText = JOptionPane.showInputDialog(None, "Decrypted String", "Encrpytion", JOptionPane.PLAIN_MESSAGE, None, None, str("Request Type is not selected"))
        



    
    # Get row Count
    def getRowCount(self):
        try:
            return len(self._log)
        except:
            return 0

    # Get column count
    def getColumnCount(self):
        return 3

   
    # Get Column Name
    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "SR"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "Method"
        
        return ""

    
    #Get the value of the Decrypted Request Table column
    def getValueAt(self, rowIndex, columnIndex):

        self.totalrow = self.logTable.getRowCount()
        if rowIndex < self.getRowCount() and columnIndex < self.getColumnCount():
            logEntry = self._log[rowIndex]
            if columnIndex == 0:
                return str(rowIndex + 1)
            if columnIndex == 1:
                return logEntry._url
            if columnIndex == 2:
                return logEntry._method
            
            return ""
        else:
            self.callbacks.printError("Table is empty")

    

    # Send the Decrypted request to the scanner
    def sendtoscanner(self,event):
        row = self.logTable.getSelectedRows()
        for rows in row:
            
            logEntry = self._log[rows]
           
            if logEntry._service.getProtocol() == "https":
                usehttps = True
            else:
                usehttps = False

            self.callbacks.doActiveScan(logEntry._service.getHost(),logEntry._service.getPort(),usehttps,logEntry._request)

    # send the Decrypted Request to the Repeater
    def sendtorepeater(self,event):
        row = self.logTable.getSelectedRows()
        for rows in row:
            
            logEntry = self._log[rows]
           
            
            if logEntry._service.getProtocol() == "https":
                usehttps = True
            else:
                usehttps = False

            self.callbacks.sendToRepeater(logEntry._service.getHost(),logEntry._service.getPort(),usehttps,logEntry._request,'')

    #Send the Decrypted request to the Intruder
    def sendtointruder(self,event):
        row = self.logTable.getSelectedRows()
        for rows in row:
            
            logEntry = self._log[rows]
           
            
            if logEntry._service.getProtocol() == "https":
                usehttps = True
            else:
                usehttps = False

            self.callbacks.sendToIntruder(logEntry._service.getHost(),logEntry._service.getPort(),usehttps,logEntry._request)


    #Repeat the decrypted Request
    def resendrequest(self,event):
        row = self.logTable.getSelectedRows()
        for rows in row:
            logEntry = self._log[rows]
            thread = Thread(target=self.callbacks.makeHttpRequest, args=(logEntry._service,logEntry._request))
            thread.start()
            

   
    #Message Editor Hanlder for Decrpyted Request Messages
    def getHttpService(self):
        return self._currentlyDisplayedservice

    def getRequest(self):
        return self._currentlyDisplayedrequest

    def getResponse(self):
        return self._currentlyDisplayedresponse

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log[row]
        self._extender.requestViewer.setMessage(logEntry._request, True)
        self._extender.responseViewer.setMessage(self._extender.helpers.stringToBytes(logEntry._response), False)
        self._extender._currentlyDisplayedrequest = logEntry._request
        self._extender._currentlyDisplayedresponse = logEntry._response
        self._extender._currentlyDisplayedservice = logEntry._service
        
        
        JTable.changeSelection(self, row, col, toggle, extend)

#Store the Decrypted Requests
class LogEntry:
    def __init__(self, sr,url, method, request, response,service):
        self._sr = sr
        self._url = url
        self._method = method
        self._request = request
        self._response = response
        self._service = service
       