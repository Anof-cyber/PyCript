from burp import (IBurpExtender, ITab,IMessageEditorTabFactory,IMessageEditorTab,IContextMenuFactory, IContextMenuInvocation,IMessageEditorController,IHttpListener)
from java.awt import (BorderLayout,Font,Color,Dimension)
from javax.swing import (JTabbedPane,JPanel ,JRadioButton,ButtonGroup,JRadioButton,JLabel,BorderFactory,JLayeredPane,JComboBox,
JSeparator,JButton,JToggleButton,JCheckBox,JScrollPane,GroupLayout,LayoutStyle,JFileChooser,JMenuItem,JOptionPane,JTable,JSplitPane,JPopupMenu, BoxLayout, JTextArea,ScrollPaneConstants,JTextField)
from javax.swing.table import AbstractTableModel;
from javax.swing.filechooser import FileNameExtensionFilter
from java.lang import Short
from javax.swing.border import EmptyBorder
import sys
from threading import Thread,Lock

from pycript.Requesttab import CriptInputTab
from pycript.Responsetab import ResponeCriptInputTab
from pycript.Reqcheck import DecryptRequest,EncryptRequest
from pycript.stringcrypto import StringCrypto
from pycript.gui import create_third_tab_elements

errorlogtextbox = None
errorlogcheckbox = None


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
        callbacks.printOutput("Version: 0.2")
        callbacks.printOutput("GitHub - https://github.com/Anof-cyber/PyCript")
        callbacks.printOutput("Website - https://souravkalal.tech/")
        callbacks.printOutput("Documentation - https://pycript.souravkalal.tech/")
        
        callbacks.registerContextMenuFactory(self)

        #Some Config and data related variables
        self._log = list()
        self._lock = Lock()
        global errorlogtextbox, errorlogcheckbox
        self.selectedrequesttpye = None
        self.selectedresponsetpye = None
        self.selected_request_inc_ex_ctype = None
        

        # Mlutiple tab UI
        self.tab = JPanel()
        self.tabbedPane = JTabbedPane()
        self.tab.add("Center", self.tabbedPane) 

        # Creating First Tab as Config Tab
        self.firstTab = JPanel()
        self.firstTab.layout = BorderLayout()
        self.tabbedPane.addTab("Config", self.firstTab)

        # Creating Second Tab as Decrypted Request Tab
        self.secondTab = JPanel()
        self.secondTab.layout = BorderLayout()
        self.tabbedPane.addTab("Decrypted Request", self.secondTab)

        # Creating Third Tab as Logger Tab
        self.thirdTab = JPanel()
        self.thirdTab.layout = BorderLayout()
        self.tabbedPane.addTab("Log",self.thirdTab)


        #Creating UI for Third Log Tab  

        # Loading Few UI Component for Log Tab from another function 
        errorlogcheckbox, scroll_pane, errorlogtextbox = create_third_tab_elements() 

        self.errorclear_button = JButton("Clear",actionPerformed=self.clearerrortext)
        self.newlogpanel = JPanel()
        self.newlogpanel.add(errorlogcheckbox)
        self.newlogpanel.add(self.errorclear_button)
        self.thirdTab.add(self.newlogpanel, BorderLayout.PAGE_START)
        self.thirdTab.add(scroll_pane, BorderLayout.CENTER)


        # UI Component for Second Decrypted Tab

        # Creating Right click menu Table in Second Decrypted Tab
        popupMenu = JPopupMenu()
        sendscannerItem = JMenuItem("Send to Active Scanner", actionPerformed=self.sendtoscanner)
        sendRepeaterItem = JMenuItem("Send to Repeater", actionPerformed=self.sendtorepeater)
        sendIntruderItem = JMenuItem("Send to Intruder", actionPerformed=self.sendtointruder)
        repeatrequest = JMenuItem("Resend HTTP Request", actionPerformed=self.resendrequest)
        popupMenu.add(sendscannerItem)
        popupMenu.add(sendRepeaterItem)
        popupMenu.add(sendIntruderItem)
        popupMenu.add(repeatrequest)

        # Creating table for Second Decryted request tab
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

        # Creating Request and Response Text BOX UI for decrypted request tab
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

        # Register our extension for ITab in burp suite
        callbacks.addSuiteTab(self)


        # Creating UI for First Config Tab (Created using Java NetBeans)        

        # Request Type UI
        self.requestlayerpane = JLayeredPane();
        self.Requestypelabel = JLabel();
        self.Requestypelabel.setText("Request Type");
        self.Requestypelabel.setFont(Font("Segoe UI", 1, 14))
        
        self.RequestTypeRadioGroup = ButtonGroup()
        
        self.CustomBodyRadio = JRadioButton();
        self.RequestTypeRadioGroup.add(self.CustomBodyRadio);
        self.CustomBodyRadio.setText("Complete Body");
        self.CustomBodyRadio.addActionListener(self.requestypelistner)
        
		
        self.parametervalueRadio = JRadioButton();
        self.RequestTypeRadioGroup.add(self.parametervalueRadio);
        self.parametervalueRadio.setText("Parameter Value");
        self.parametervalueRadio.addActionListener(self.requestypelistner)
        
        self.paramkeyvalueRadio = JRadioButton();
        self.RequestTypeRadioGroup.add(self.paramkeyvalueRadio);
        self.paramkeyvalueRadio.setText("Parameter Key and Value");
        self.paramkeyvalueRadio.addActionListener(self.requestypelistner)
		
        self.CustomRequestRadio = JRadioButton();
        self.RequestTypeRadioGroup.add(self.CustomRequestRadio);
        self.CustomRequestRadio.setText("Custom Request");
        self.CustomRequestRadio.addActionListener(self.requestypelistner)
		
        self.CustomRequestheaderRadio = JRadioButton();
        self.RequestTypeRadioGroup.add(self.CustomRequestheaderRadio);
        self.CustomRequestheaderRadio.setText("Custom Request (Edit Header)");
        self.CustomRequestheaderRadio.addActionListener(self.requestypelistner)
		
        self.RequestTypeNoneRadio = JRadioButton();
        self.RequestTypeRadioGroup.add(self.RequestTypeNoneRadio);
        self.RequestTypeNoneRadio.setText("None");
        self.RequestTypeNoneRadio.setSelected(True)
        self.RequestTypeNoneRadio.addActionListener(self.requestypelistner)
		
		
		# Response Type UI
        self.responslayerpane = JLayeredPane();
        self.Responsetypelabel1 = JLabel();
        self.Responsetypelabel1.setText("Response Type");
        self.Responsetypelabel1.setFont(Font("Segoe UI", 1, 14))
        
        self.ReesponseTypeRadioGroup = ButtonGroup()
        
        self.responseCustomBodyRadio = JRadioButton();
        self.ReesponseTypeRadioGroup.add(self.responseCustomBodyRadio);
        self.responseCustomBodyRadio.setText("Complete Body");
        self.responseCustomBodyRadio.addActionListener(self.responsetypelister)
        
        self.responsejsonvalueradio = JRadioButton();
        self.ReesponseTypeRadioGroup.add(self.responsejsonvalueradio);
        self.responsejsonvalueradio.setText("JSON Value")
        self.responsejsonvalueradio.addActionListener(self.responsetypelister)
        
        self.responsejsonkeyvalueradio = JRadioButton();
        self.ReesponseTypeRadioGroup.add(self.responsejsonkeyvalueradio);
        self.responsejsonkeyvalueradio.setText("JSON Key and Value");
        self.responsejsonkeyvalueradio.addActionListener(self.responsetypelister)
        
        self.ResponseTypeNoneRadio = JRadioButton();
        self.ReesponseTypeRadioGroup.add(self.ResponseTypeNoneRadio);
        self.ResponseTypeNoneRadio.setText("None");
        self.ResponseTypeNoneRadio.setSelected(True)
        self.ResponseTypeNoneRadio.addActionListener(self.responsetypelister)
		
		
		
		#Additional Setting UI
        self.additionallayerpane = JLayeredPane();
        
        self.AdditionalSettinglabel = JLabel();
        self.AdditionalSettinglabel.setText("Additional Setting");
        self.AdditionalSettinglabel.setFont(Font("Segoe UI", 1, 14))
        
        self.languagelabel = JLabel();
        self.languagelabel.setText("Language");
        
        self.langdata = ("JavaScript", "Python", "Java Jar")
        self.languagecombobox = JComboBox(self.langdata)
		
        
        self.reqmethodlabel = JLabel();
        self.reqmethodlabel.setText("Encryption and Decryption Method(Only for Request)");
		
        self.methoddata = ("GET", "BODY", "BOTH")
        self.reqmethodcombobox = JComboBox(self.methoddata);
		
        self.reqresponselabel = JLabel();
        self.reqresponselabel.setText("Encryption Decryption For");
		
        self.reqresponsedata = ("Request", "Response", "Both")
        self.reqresponsecombobox = JComboBox(self.reqresponsedata);

        
        # Additional Settings UI
        self.autoencryptlayerpane = JLayeredPane();
        self.AutoEncryptLabel = JLabel();
        self.AutoEncryptLabel.setFont(Font("Segoe UI", 1, 14));
        self.AutoEncryptLabel.setText("Auto Encrypt The Request (Request Type should be selected)")
        
        self.AutoEncryptLabel1 = JLabel();
        self.AutoEncryptLabel1.setFont(Font("Segoe UI", 1, 14))
        self.AutoEncryptLabel1.setText("Auto Encrypt Tool Type");
        
        self.Autoencryptonoffbutton = JToggleButton();
        self.Autoencryptonoffbutton.setEnabled(False)
        self.Autoencryptonoffbutton.setText("Turn On");
        self.Autoencryptonoffbutton.setBackground(Color(255, 21, 0))
        self.Autoencryptonoffbutton.setForeground(Color(255, 255, 255));
        self.Autoencryptonoffbutton.setFont(Font("Segoe UI", 1, 15));
        self.Autoencryptonoffbutton.setToolTipText("");
        self.Autoencryptonoffbutton.addItemListener(self.Autoencryptstatuslistner)
        
        self.AutoencryptTogglestatuslabel = JLabel();
        self.AutoencryptTogglestatuslabel.setText("Current Status: OFF");
        
        self.FileChooserErrorlabel1 = JLabel();
        self.FileChooserErrorlabel1.setForeground(Color(237, 121, 5));
        self.FileChooserErrorlabel1.setText("Cannot Turn On Unless Request Type and Tool Type is not selected");
		
        jSeparator1 =JSeparator();
        
        self.AutoencryptTooltypeScanner = JCheckBox();
        self.AutoencryptTooltypeScanner.setText("Scanner");
        self.AutoencryptTooltypeScanner.addActionListener(self.encrypttoollistener)
        
        self.AutoencryptTooltypeExtender = JCheckBox();
        self.AutoencryptTooltypeExtender.setText("Extender");
        self.AutoencryptTooltypeExtender.addActionListener(self.encrypttoollistener)
        
        self.AutoencryptTooltypeRepeater = JCheckBox();
        self.AutoencryptTooltypeRepeater.addActionListener(self.encrypttoollistener)
        self.AutoencryptTooltypeRepeater.setText("Repeater");
        
        self.AutoencryptTooltypeProxy = JCheckBox();
        self.AutoencryptTooltypeProxy.addActionListener(self.encrypttoollistener)
        self.AutoencryptTooltypeProxy.setText("Proxy");
		
        self.AutoencryptTooltypeIntruder = JCheckBox();
        self.AutoencryptTooltypeIntruder.addActionListener(self.encrypttoollistener)
        self.AutoencryptTooltypeIntruder.setText("Intruder");
        
        
        # Request Encryption Decryption File Selection UI
        self.requestscriptfilelayerpane = JLayeredPane();
        self.FileChooserLabel = JLabel();
        self.FileChooserLabel.setFont(Font("Segoe UI", 1, 14));
        self.FileChooserLabel.setText("Request Encryption Deryption Files");
        
        self.Encryptionfilelabel = JLabel();
        self.Encryptionfilelabel.setText("Encryption File");

        self.Decryptionfilelabel = JLabel();
        self.Decryptionfilelabel.setText("Decryption File");
		
        self.Encryptionfilechooserbutton = JButton();
        self.Encryptionfilechooserbutton.addActionListener(self.importencryptionjsfile)
        self.Encryptionfilechooserbutton.setText("Choose File");
		
        self.Decryptionfilechooserbutton = JButton();
        self.Decryptionfilechooserbutton.addActionListener(self.importdecryptionjsfile)
        self.Decryptionfilechooserbutton.setText("Choose File");
		
        self.requestencrpytionpath = JLabel();
        self.requestencrpytionpath.setText("");
        
        self.requestdecryptionpath = JLabel();
        self.requestdecryptionpath.setText("");


        # Response encryption decryption file selection UI
        self.responescriptfilelayerpane = JLayeredPane();
        self.responseFileChooserLabel = JLabel();
        self.responseFileChooserLabel.setFont(Font("Segoe UI", 1, 14));
        self.responseFileChooserLabel.setText("Response Encryption Deryption Files");
        
        self.ResponseEncryptionfilelabel = JLabel();
        self.ResponseEncryptionfilelabel.setText("Encryption File");
        
        self.ResponseDecryptionfilelabel = JLabel();
        self.ResponseDecryptionfilelabel.setText("Decryption File");
        


        self.ResponseEncryptionfilechooserbutton = JButton();
        self.ResponseEncryptionfilechooserbutton.setText("Choose File");
        self.ResponseEncryptionfilechooserbutton.addActionListener(self.importresponseencfile)

        self.RsponseDecryptionfilechooserbutton = JButton();
        self.RsponseDecryptionfilechooserbutton.setText("Choose File");
        self.RsponseDecryptionfilechooserbutton.addActionListener(self.importresponsedecfile)
        
        self.responseencryptionpath = JLabel();
        self.responseencryptionpath.setText("");
        
        self.responsedecryptionpath = JLabel();
        self.responsedecryptionpath.setText("");


        # Trying to load Request encryption decryption file path from previously slected location
        self.reqencpath = callbacks.loadExtensionSetting('requestencryptionfilesave')
        self.reqdecpath = callbacks.loadExtensionSetting('requestdecryptionfilesave')
        
        if self.reqencpath == None:
            self.encryptionfilepath = None
        else:
            self.encryptionfilepath = self.reqencpath
            self.requestencrpytionpath.setText(self.encryptionfilepath)

        if self.reqdecpath == None:
            self.decryptionfilepath = None
        else:
            self.decryptionfilepath = self.reqdecpath
            self.requestdecryptionpath.setText(self.decryptionfilepath)


        # # Trying to load Response encryption decryption file path from previously slected location
        self.respencpath = callbacks.loadExtensionSetting('responseencryptionfilesave')
        self.respdecpath = callbacks.loadExtensionSetting('responsedecryptionfilesave')

        if self.respencpath == None:
            self.responseencryptionfilepath = None;
        else:
            self.responseencryptionfilepath = self.reqencpath
            self.responseencryptionpath.setText(self.responseencryptionfilepath);
        
        if self.respdecpath == None:
            self.responsedecryptionfilepath = None;
        else:
            self.responsedecryptionfilepath = self.respdecpath
            self.responsedecryptionpath.setText(self.responsedecryptionfilepath)
        

        ## Request/ Response need to be loaded after all UI 
        ## Creating a seperate request and response message editor tab to show decrypted messages
        request_tab_factory = RequestTabFactory(self)
        response_tab_factory = ResponseTabFactory(self)
        callbacks.registerMessageEditorTabFactory(request_tab_factory)
        callbacks.registerMessageEditorTabFactory(response_tab_factory)


        
        # Request include exclude parameters UI settings

        Requestparamlist = JLayeredPane();
        Requestparamlist.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)))

        Requestparamlabel = JLabel();
        Requestparamlabel.setText("Request parameters to Include or Exclude");
        Requestparamlabel.setFont(Font("Segoe UI", 1, 14));

        Requestparamlabel3 = JLabel();
        Requestparamlabel3.setText("Seperated by , Coma [Case Sensitive]");
        Requestparamlabel3.setForeground(Color(237, 121, 5));

        self.Reuestparameterbuttongroup = ButtonGroup()

        requestparamignorebutton = JRadioButton();
        self.Reuestparameterbuttongroup.add(requestparamignorebutton);
        requestparamignorebutton.setText("Exclude Parameters");
        requestparamignorebutton.addActionListener(self.requestparamlistener)

        requestparamconsiderbutton = JRadioButton();
        self.Reuestparameterbuttongroup.add(requestparamconsiderbutton);
        requestparamconsiderbutton.setText("Include Parameters");
        requestparamconsiderbutton.addActionListener(self.requestparamlistener)

        self.Requestparamnonebutton = JRadioButton();
        self.Reuestparameterbuttongroup.add(self.Requestparamnonebutton);
        self.Requestparamnonebutton.setSelected(True);
        self.Requestparamnonebutton.setText("None");
        self.Requestparamnonebutton.addActionListener(self.requestparamlistener)

        self.requestparamlist = JTextField();
        self.requestparamlist.setColumns(5);
        self.requestparamlist.setText("Password,current_password");

        
        


        # Response exclude include Parameters UI


        Responseparamlist = JLayeredPane();
        Responseparamlist.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)));

        self.Responseparambuttongroup = ButtonGroup()

        self.responseparamnonebutton = JRadioButton();
        self.Responseparambuttongroup.add(self.responseparamnonebutton);
        self.responseparamnonebutton.setSelected(True);
        self.responseparamnonebutton.setText("None");
        self.responseparamnonebutton.addActionListener(self.responseparamlistener)

        responseparamignorebutton1 = JRadioButton();
        responseparamignorebutton1.setText("Exclude Parameters");
        self.Responseparambuttongroup.add(responseparamignorebutton1);
        responseparamignorebutton1.addActionListener(self.responseparamlistener)

        responseparamconsiderbutton1 = JRadioButton();
        self.Responseparambuttongroup.add(responseparamconsiderbutton1);
        responseparamconsiderbutton1.setText("Include Parameters");
        responseparamconsiderbutton1.addActionListener(self.responseparamlistener)

        
        Responseparamlabel1 = JLabel();
        Responseparamlabel1.setText("Response parameters to Include or Exclude");
        Responseparamlabel1.setFont(Font("Segoe UI", 1, 14));



        self.responseparamlist1 = JTextField();
        self.responseparamlist1.setColumns(5);
        self.responseparamlist1.setText("Password,current_password");


        Responseparamlabel4 = JLabel();
        Responseparamlabel4.setText("Seperated by , Coma [Case Sensitive]");
        Responseparamlabel4.setForeground(Color(237, 121, 5));


        Requestparamlist.setLayer(Requestparamlabel, JLayeredPane.DEFAULT_LAYER);
        Requestparamlist.setLayer(requestparamignorebutton, JLayeredPane.DEFAULT_LAYER);
        Requestparamlist.setLayer(requestparamconsiderbutton, JLayeredPane.DEFAULT_LAYER);
        Requestparamlist.setLayer(self.requestparamlist, JLayeredPane.DEFAULT_LAYER);
        Requestparamlist.setLayer(Requestparamlabel3, JLayeredPane.DEFAULT_LAYER);
        Requestparamlist.setLayer(self.Requestparamnonebutton,JLayeredPane.DEFAULT_LAYER);

        RequestparamlistLayout = GroupLayout(Requestparamlist);
        Requestparamlist.setLayout(RequestparamlistLayout);
        RequestparamlistLayout.setHorizontalGroup(
            RequestparamlistLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(RequestparamlistLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(RequestparamlistLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(Requestparamlabel)
                    .addGroup(RequestparamlistLayout.createSequentialGroup()
                        .addComponent(requestparamignorebutton)
                        .addGap(18, 18, 18)
                        .addComponent(requestparamconsiderbutton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.Requestparamnonebutton))
                    .addComponent(self.requestparamlist, GroupLayout.PREFERRED_SIZE, 331, GroupLayout.PREFERRED_SIZE)
                    .addComponent(Requestparamlabel3))
                .addContainerGap(267, Short.MAX_VALUE))
        );
        RequestparamlistLayout.setVerticalGroup(
            RequestparamlistLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(RequestparamlistLayout.createSequentialGroup()
                .addComponent(Requestparamlabel)
                .addGap(18, 18, 18)
                .addGroup(RequestparamlistLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(requestparamignorebutton)
                    .addComponent(requestparamconsiderbutton)
                    .addComponent(self.Requestparamnonebutton))
                .addGap(17, 17, 17)
                .addComponent(Requestparamlabel3)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.requestparamlist, GroupLayout.PREFERRED_SIZE, 37, GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        

        Responseparamlist.setLayer(Responseparamlabel1, JLayeredPane.DEFAULT_LAYER);
        Responseparamlist.setLayer(responseparamignorebutton1, JLayeredPane.DEFAULT_LAYER);
        Responseparamlist.setLayer(responseparamconsiderbutton1, JLayeredPane.DEFAULT_LAYER);
        Responseparamlist.setLayer(self.responseparamlist1, JLayeredPane.DEFAULT_LAYER);
        Responseparamlist.setLayer(Responseparamlabel4, JLayeredPane.DEFAULT_LAYER);
        Responseparamlist.setLayer(self.responseparamnonebutton, JLayeredPane.DEFAULT_LAYER);

        ResponseparamlistLayout = GroupLayout(Responseparamlist);
        Responseparamlist.setLayout(ResponseparamlistLayout);
        ResponseparamlistLayout.setHorizontalGroup(
            ResponseparamlistLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(ResponseparamlistLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(ResponseparamlistLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(Responseparamlabel1)
                    .addGroup(ResponseparamlistLayout.createSequentialGroup()
                        .addComponent(responseparamignorebutton1)
                        .addGap(18, 18, 18)
                        .addComponent(responseparamconsiderbutton1)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(self.responseparamnonebutton))
                    .addComponent(self.responseparamlist1, GroupLayout.PREFERRED_SIZE, 331, GroupLayout.PREFERRED_SIZE)
                    .addComponent(Responseparamlabel4))
                .addContainerGap(261, Short.MAX_VALUE))
        );
        ResponseparamlistLayout.setVerticalGroup(
            ResponseparamlistLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(ResponseparamlistLayout.createSequentialGroup()
                .addComponent(Responseparamlabel1)
                .addGap(18, 18, 18)
                .addGroup(ResponseparamlistLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(responseparamignorebutton1)
                    .addComponent(responseparamconsiderbutton1)
                    .addComponent(self.responseparamnonebutton))
                .addGap(17, 17, 17)
                .addComponent(Responseparamlabel4)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.responseparamlist1, GroupLayout.PREFERRED_SIZE, 37, GroupLayout.PREFERRED_SIZE)
                .addGap(0, 42, Short.MAX_VALUE))
        );



        # Config Tab UI Placement options
        self.requestlayerpane.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)));
        self.requestlayerpane.setLayer(self.Requestypelabel, JLayeredPane.DEFAULT_LAYER);
        self.requestlayerpane.setLayer(self.CustomBodyRadio, JLayeredPane.DEFAULT_LAYER);
        self.requestlayerpane.setLayer(self.parametervalueRadio, JLayeredPane.DEFAULT_LAYER);
        self.requestlayerpane.setLayer(self.paramkeyvalueRadio, JLayeredPane.DEFAULT_LAYER);
        self.requestlayerpane.setLayer(self.CustomRequestRadio, JLayeredPane.DEFAULT_LAYER);
        self.requestlayerpane.setLayer(self.CustomRequestheaderRadio, JLayeredPane.DEFAULT_LAYER);
        self.requestlayerpane.setLayer(self.RequestTypeNoneRadio, JLayeredPane.DEFAULT_LAYER);

        self.requestlayerpaneLayout = GroupLayout(self.requestlayerpane);
        self.requestlayerpane.setLayout(self.requestlayerpaneLayout);
        self.requestlayerpaneLayout.setHorizontalGroup(
            self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.requestlayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.Requestypelabel)
                    .addGroup(self.requestlayerpaneLayout.createSequentialGroup()
                        .addGroup(self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(self.CustomBodyRadio)
                            .addComponent(self.paramkeyvalueRadio)
                            .addComponent(self.CustomRequestheaderRadio))
                        .addGap(2, 2, 2)
                        .addGroup(self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(self.RequestTypeNoneRadio)
                            .addComponent(self.CustomRequestRadio)
                            .addComponent(self.parametervalueRadio))))
                .addContainerGap(53, Short.MAX_VALUE))
        );
        self.requestlayerpaneLayout.setVerticalGroup(
            self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.requestlayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.Requestypelabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.CustomBodyRadio)
                    .addComponent(self.parametervalueRadio))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.paramkeyvalueRadio)
                    .addComponent(self.CustomRequestRadio))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.requestlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.RequestTypeNoneRadio)
                    .addComponent(self.CustomRequestheaderRadio))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );








        self.responslayerpane.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)));
        self.responslayerpane.setLayer(self.Responsetypelabel1, JLayeredPane.DEFAULT_LAYER);
        self.responslayerpane.setLayer(self.responseCustomBodyRadio, JLayeredPane.DEFAULT_LAYER);
        self.responslayerpane.setLayer(self.responsejsonvalueradio, JLayeredPane.DEFAULT_LAYER);
        self.responslayerpane.setLayer(self.responsejsonkeyvalueradio, JLayeredPane.DEFAULT_LAYER);
        self.responslayerpane.setLayer(self.ResponseTypeNoneRadio, JLayeredPane.DEFAULT_LAYER);

        self.responslayerpaneLayout = GroupLayout(self.responslayerpane);
        self.responslayerpane.setLayout(self.responslayerpaneLayout);
        self.responslayerpaneLayout.setHorizontalGroup(
            self.responslayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.responslayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.responslayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.Responsetypelabel1)
                    .addGroup(self.responslayerpaneLayout.createSequentialGroup()
                        .addGroup(self.responslayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(self.responsejsonkeyvalueradio)
                            .addComponent(self.responseCustomBodyRadio))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(self.responslayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(self.responsejsonvalueradio)
                            .addComponent(self.ResponseTypeNoneRadio))))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        self.responslayerpaneLayout.setVerticalGroup(
            self.responslayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.responslayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.Responsetypelabel1)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.responslayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.responseCustomBodyRadio)
                    .addComponent(self.responsejsonvalueradio))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.responslayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.responsejsonkeyvalueradio)
                    .addComponent(self.ResponseTypeNoneRadio))
                .addContainerGap(38, Short.MAX_VALUE))
        );







        self.additionallayerpane.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)));
        self.additionallayerpane.setLayer(self.AdditionalSettinglabel, JLayeredPane.DEFAULT_LAYER);
        self.additionallayerpane.setLayer(self.languagelabel, JLayeredPane.DEFAULT_LAYER);
        self.additionallayerpane.setLayer(self.languagecombobox, JLayeredPane.DEFAULT_LAYER);
        self.additionallayerpane.setLayer(self.reqmethodlabel, JLayeredPane.DEFAULT_LAYER);
        self.additionallayerpane.setLayer(self.reqmethodcombobox, JLayeredPane.DEFAULT_LAYER);
        self.additionallayerpane.setLayer(self.reqresponselabel, JLayeredPane.DEFAULT_LAYER);
        self.additionallayerpane.setLayer(self.reqresponsecombobox, JLayeredPane.DEFAULT_LAYER);

        self.additionallayerpaneLayout = GroupLayout(self.additionallayerpane);
        self.additionallayerpane.setLayout(self.additionallayerpaneLayout);
        self.additionallayerpaneLayout.setHorizontalGroup(
            self.additionallayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.additionallayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.additionallayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.AdditionalSettinglabel)
                    .addGroup(self.additionallayerpaneLayout.createSequentialGroup()
                        .addGroup(self.additionallayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(self.reqmethodlabel)
                            .addGroup(self.additionallayerpaneLayout.createSequentialGroup()
                                .addComponent(self.languagelabel)
                                .addGap(18, 18, 18)
                                .addComponent(self.languagecombobox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.reqmethodcombobox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                    .addGroup(self.additionallayerpaneLayout.createSequentialGroup()
                        .addComponent(self.reqresponselabel)
                        .addGap(18, 18, 18)
                        .addComponent(self.reqresponsecombobox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(25, Short.MAX_VALUE))
        );
        self.additionallayerpaneLayout.setVerticalGroup(
            self.additionallayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.additionallayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.AdditionalSettinglabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.additionallayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.languagelabel)
                    .addComponent(self.languagecombobox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.additionallayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.reqmethodlabel)
                    .addComponent(self.reqmethodcombobox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.additionallayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.reqresponselabel)
                    .addComponent(self.reqresponsecombobox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );




        self.autoencryptlayerpane.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)));
        self.autoencryptlayerpane.setLayer(self.AutoEncryptLabel, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.AutoEncryptLabel1, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.Autoencryptonoffbutton, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.AutoencryptTogglestatuslabel, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.FileChooserErrorlabel1, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(jSeparator1, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.AutoencryptTooltypeScanner, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.AutoencryptTooltypeExtender, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.AutoencryptTooltypeRepeater, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.AutoencryptTooltypeProxy, JLayeredPane.DEFAULT_LAYER);
        self.autoencryptlayerpane.setLayer(self.AutoencryptTooltypeIntruder, JLayeredPane.DEFAULT_LAYER);

        self.autoencryptlayerpaneLayout = GroupLayout(self.autoencryptlayerpane);
        self.autoencryptlayerpane.setLayout(self.autoencryptlayerpaneLayout);
        self.autoencryptlayerpaneLayout.setHorizontalGroup(
            self.autoencryptlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.autoencryptlayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.autoencryptlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.AutoEncryptLabel)
                    .addGroup(self.autoencryptlayerpaneLayout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addGroup(self.autoencryptlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addComponent(self.FileChooserErrorlabel1)
                            .addGroup(self.autoencryptlayerpaneLayout.createSequentialGroup()
                                .addComponent(self.Autoencryptonoffbutton)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.AutoencryptTogglestatuslabel))
                            .addComponent(self.AutoEncryptLabel1)
                            .addGroup(self.autoencryptlayerpaneLayout.createSequentialGroup()
                                .addComponent(self.AutoencryptTooltypeScanner)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(self.AutoencryptTooltypeExtender)
                                .addGap(18, 18, 18)
                                .addComponent(self.AutoencryptTooltypeRepeater))
                            .addGroup(self.autoencryptlayerpaneLayout.createSequentialGroup()
                                .addComponent(self.AutoencryptTooltypeProxy)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(self.AutoencryptTooltypeIntruder))))
                    .addComponent(jSeparator1, GroupLayout.PREFERRED_SIZE, 295, GroupLayout.PREFERRED_SIZE))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        self.autoencryptlayerpaneLayout.setVerticalGroup(
            self.autoencryptlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.autoencryptlayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.AutoEncryptLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.autoencryptlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.Autoencryptonoffbutton)
                    .addComponent(self.AutoencryptTogglestatuslabel))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(self.FileChooserErrorlabel1)
                .addGap(5, 5, 5)
                .addComponent(jSeparator1, GroupLayout.PREFERRED_SIZE, 10, GroupLayout.PREFERRED_SIZE)
                .addGap(3, 3, 3)
                .addComponent(self.AutoEncryptLabel1)
                .addGap(18, 18, 18)
                .addGroup(self.autoencryptlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.AutoencryptTooltypeScanner)
                    .addComponent(self.AutoencryptTooltypeExtender)
                    .addComponent(self.AutoencryptTooltypeRepeater))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.autoencryptlayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.AutoencryptTooltypeProxy)
                    .addComponent(self.AutoencryptTooltypeIntruder))
                .addContainerGap(32, Short.MAX_VALUE))
        );




        self.requestscriptfilelayerpane.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)));
        self.requestscriptfilelayerpane.setLayer(self.FileChooserLabel, JLayeredPane.DEFAULT_LAYER);
        self.requestscriptfilelayerpane.setLayer(self.Encryptionfilelabel, JLayeredPane.DEFAULT_LAYER);
        self.requestscriptfilelayerpane.setLayer(self.Decryptionfilelabel, JLayeredPane.DEFAULT_LAYER);
        self.requestscriptfilelayerpane.setLayer(self.Encryptionfilechooserbutton, JLayeredPane.DEFAULT_LAYER);
        self.requestscriptfilelayerpane.setLayer(self.Decryptionfilechooserbutton, JLayeredPane.DEFAULT_LAYER);
        self.requestscriptfilelayerpane.setLayer(self.requestencrpytionpath, JLayeredPane.DEFAULT_LAYER);
        self.requestscriptfilelayerpane.setLayer(self.requestdecryptionpath, JLayeredPane.DEFAULT_LAYER);

        self.requestscriptfilelayerpaneLayout = GroupLayout(self.requestscriptfilelayerpane);
        self.requestscriptfilelayerpane.setLayout(self.requestscriptfilelayerpaneLayout);
        self.requestscriptfilelayerpaneLayout.setHorizontalGroup(
            self.requestscriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.requestscriptfilelayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.requestscriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.FileChooserLabel)
                    .addGroup(self.requestscriptfilelayerpaneLayout.createSequentialGroup()
                        .addComponent(self.Encryptionfilelabel)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.Encryptionfilechooserbutton)
                        .addGap(18, 18, 18)
                        .addComponent(self.requestencrpytionpath))
                    .addGroup(self.requestscriptfilelayerpaneLayout.createSequentialGroup()
                        .addComponent(self.Decryptionfilelabel)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.Decryptionfilechooserbutton)
                        .addGap(18, 18, 18)
                        .addComponent(self.requestdecryptionpath)))
                .addContainerGap(341, Short.MAX_VALUE))
        );
        self.requestscriptfilelayerpaneLayout.setVerticalGroup(
            self.requestscriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.requestscriptfilelayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.FileChooserLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.requestscriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.Encryptionfilelabel)
                    .addComponent(self.Encryptionfilechooserbutton)
                    .addComponent(self.requestencrpytionpath))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.requestscriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.Decryptionfilelabel)
                    .addComponent(self.Decryptionfilechooserbutton)
                    .addComponent(self.requestdecryptionpath))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );




        self.responescriptfilelayerpane.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)));
        self.responescriptfilelayerpane.setLayer(self.responseFileChooserLabel, JLayeredPane.DEFAULT_LAYER);
        self.responescriptfilelayerpane.setLayer(self.ResponseEncryptionfilelabel, JLayeredPane.DEFAULT_LAYER);
        self.responescriptfilelayerpane.setLayer(self.ResponseDecryptionfilelabel, JLayeredPane.DEFAULT_LAYER);
        self.responescriptfilelayerpane.setLayer(self.ResponseEncryptionfilechooserbutton, JLayeredPane.DEFAULT_LAYER);
        self.responescriptfilelayerpane.setLayer(self.RsponseDecryptionfilechooserbutton, JLayeredPane.DEFAULT_LAYER);
        self.responescriptfilelayerpane.setLayer(self.responseencryptionpath, JLayeredPane.DEFAULT_LAYER);
        self.responescriptfilelayerpane.setLayer(self.responsedecryptionpath, JLayeredPane.DEFAULT_LAYER);

        self.responescriptfilelayerpaneLayout = GroupLayout(self.responescriptfilelayerpane);
        self.responescriptfilelayerpane.setLayout(self.responescriptfilelayerpaneLayout);
        self.responescriptfilelayerpaneLayout.setHorizontalGroup(
            self.responescriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.responescriptfilelayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(self.responescriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.responseFileChooserLabel)
                    .addGroup(self.responescriptfilelayerpaneLayout.createSequentialGroup()
                        .addComponent(self.ResponseEncryptionfilelabel)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.ResponseEncryptionfilechooserbutton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(self.responseencryptionpath))
                    .addGroup(self.responescriptfilelayerpaneLayout.createSequentialGroup()
                        .addComponent(self.ResponseDecryptionfilelabel)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.RsponseDecryptionfilechooserbutton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(self.responsedecryptionpath)))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        self.responescriptfilelayerpaneLayout.setVerticalGroup(
            self.responescriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(self.responescriptfilelayerpaneLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(self.responseFileChooserLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(self.responescriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.ResponseEncryptionfilelabel)
                    .addComponent(self.ResponseEncryptionfilechooserbutton)
                    .addComponent(self.responseencryptionpath))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(self.responescriptfilelayerpaneLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.ResponseDecryptionfilelabel)
                    .addComponent(self.RsponseDecryptionfilechooserbutton)
                    .addComponent(self.responsedecryptionpath))
                .addContainerGap(14, Short.MAX_VALUE))
        );




        layout = GroupLayout(self.firstTab);
        self.firstTab.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                    .addGroup(GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(self.requestlayerpane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.responslayerpane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.additionallayerpane))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self.autoencryptlayerpane)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                            .addComponent(self.requestscriptfilelayerpane)
                            .addComponent(self.responescriptfilelayerpane)))
                    .addGroup(GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(Requestparamlist, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(Responseparamlist, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addGap(18, 18, 18))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                    .addComponent(self.responslayerpane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                        .addComponent(self.additionallayerpane)
                        .addComponent(self.requestlayerpane)))
                .addGap(31, 31, 31)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                    .addComponent(self.autoencryptlayerpane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self.requestscriptfilelayerpane)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(self.responescriptfilelayerpane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                    .addComponent(Requestparamlist)
                    .addComponent(Responseparamlist))
                .addContainerGap(657, Short.MAX_VALUE))
        );


        
    


    # Listeners for Response type radio buttons
    def responsetypelister(self,e):
        selected = e.getSource()
        if not selected.getText() == "None":
            if None not in (self.responsedecryptionfilepath,self.responseencryptionfilepath):
                self.ResponseTypeNoneRadio.setSelected(False)
                self.selectedresponsetpye = selected.getText()
            else:
                JOptionPane.showMessageDialog(None, "Response Encryption and Decryption File Required to Start")
                self.ResponseTypeNoneRadio.setSelected(True)
                self.selectedresponsetpye = "None"
        elif selected.getText() == "None":
            self.selectedresponsetpye = "None"
            self.ResponseTypeNoneRadio.setSelected(True)

        if selected.getText() not in ["JSON Value", "JSON Key and Value"]:
            self.responseparamnonebutton.setSelected(True);



    # Listeners for Request type radio buttons
    def requestypelistner(self, e):
        selected = e.getSource()
        if not selected.getText() == "None":

            if None not in (self.decryptionfilepath,self.encryptionfilepath):
                #self.FileChooserErrorlabel.setText("");
                #self.Autoencryptonoffbutton.setEnabled(True)
                self.RequestTypeNoneRadio.setSelected(False)
                self.selectedrequesttpye = selected.getText()
                if self.AutoencryptTooltypeScanner.isSelected() or self.AutoencryptTooltypeExtender.isSelected() or self.AutoencryptTooltypeRepeater.isSelected() or self.AutoencryptTooltypeProxy.isSelected() or self.AutoencryptTooltypeIntruder.isSelected() == True:
                    self.Autoencryptonoffbutton.setEnabled(True)
            else:
                #self.FileChooserErrorlabel.setText("Encryption and Decryption File Required to Start");
                JOptionPane.showMessageDialog(None, "Request Encryption and Decryption File Required to Start")
                self.RequestTypeNoneRadio.setSelected(True)
                self.Autoencryptonoffbutton.setEnabled(False)
                self.Autoencryptonoffbutton.setSelected(False)
                self.selectedrequesttpye = "None"
        elif selected.getText() == "None":
            self.selectedrequesttpye = "None"
            self.Autoencryptonoffbutton.setEnabled(False)
            self.Autoencryptonoffbutton.setSelected(False)

        if selected.getText() not in ["Parameter Value", "Parameter Key and Value"]:
            self.Requestparamnonebutton.setSelected(True);
        




    # Listener for Request Ignore or exclude parameters radio button
    def requestparamlistener(self,e):
        selected = e.getSource()
        if not selected.getText() == "None":
            if self.selectedrequesttpye not in ["Parameter Value", "Parameter Key and Value"]:
                self.Requestparamnonebutton.setSelected(True);
                JOptionPane.showMessageDialog(None, "Selected Request type should be Parameter Value or Parameter Key and Value", "Error", JOptionPane.ERROR_MESSAGE)

            else:
                if self.requestparamlist.getText().strip() == "":
                    self.responseparamnonebutton.setSelected(True);
                    JOptionPane.showMessageDialog(None, "Parameter list cannot be empty", "Error", JOptionPane.ERROR_MESSAGE)
                else:
                    self.selected_request_inc_ex_ctype = selected.getText()


    # Listener for Response Ignore or exclude parameters radio button
    def responseparamlistener(self,e):
        selected = e.getSource()
        if not selected.getText() == "None":
            if self.selectedresponsetpye  not in ["JSON Value", "JSON Key and Value"]:
                self.responseparamnonebutton.setSelected(True);
                JOptionPane.showMessageDialog(None, "Selected Response type should be JSON Value or JSON Key and Value", "Error", JOptionPane.ERROR_MESSAGE)

            else:
                if self.responseparamlist1.getText().strip() == "":
                    self.responseparamnonebutton.setSelected(True);
                    JOptionPane.showMessageDialog(None, "Parameter list cannot be empty", "Error", JOptionPane.ERROR_MESSAGE)
                else:
                    self.selectedresp_incexctype = selected.getText()




    # handle response encryption file
    def importresponseencfile(self,e):
        chooseFile = JFileChooser()
        filter = FileNameExtensionFilter("js files", ["js"])
        chooseFile.addChoosableFileFilter(filter)
        ret = chooseFile.showDialog(self.tab, "Choose file")  
        if ret == JFileChooser.APPROVE_OPTION: 
            fileLoad = chooseFile.getSelectedFile()
            self.responseencryptionfilepath = fileLoad.getAbsolutePath()
            self.responseencryptionpath.setText(self.responseencryptionfilepath)
            self.callbacks.saveExtensionSetting("responseencryptionfilesave", self.responseencryptionfilepath)


    # handle import response decryption files
    def importresponsedecfile(self,e):
        chooseFile = JFileChooser()
        filter = FileNameExtensionFilter("js files", ["js"])
        chooseFile.addChoosableFileFilter(filter)
        ret = chooseFile.showDialog(self.tab, "Choose file")  
        if ret == JFileChooser.APPROVE_OPTION: 
            fileLoad = chooseFile.getSelectedFile()
            self.responsedecryptionfilepath = fileLoad.getAbsolutePath()
            self.responsedecryptionpath.setText(self.responsedecryptionfilepath)
            self.callbacks.saveExtensionSetting("responsedecryptionfilesave", self.responsedecryptionfilepath)


    # Handles Import for the Encryption File for request
    def importencryptionjsfile(self,e):
        chooseFile = JFileChooser()
        filter = FileNameExtensionFilter("js files", ["js"])
        chooseFile.addChoosableFileFilter(filter)    
        ret = chooseFile.showDialog(self.tab, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            fileLoad = chooseFile.getSelectedFile()
            self.encryptionfilepath = fileLoad.getAbsolutePath()
            self.requestencrpytionpath.setText(self.encryptionfilepath)
            self.callbacks.saveExtensionSetting("requestencryptionfilesave", self.encryptionfilepath)
            


    # Handle Import for Decryption File for request
    def importdecryptionjsfile(self,e):
        chooseFile = JFileChooser()
        filter = FileNameExtensionFilter("js files", ["js"])
        chooseFile.addChoosableFileFilter(filter)    
        ret = chooseFile.showDialog(self.tab, "Choose file")
        if ret == JFileChooser.APPROVE_OPTION:
            fileLoad = chooseFile.getSelectedFile()
            self.decryptionfilepath = fileLoad.getAbsolutePath()
            self.requestdecryptionpath.setText(self.decryptionfilepath)
            self.callbacks.saveExtensionSetting("requestdecryptionfilesave", self.decryptionfilepath)
            


    # Returning the Extension Tab name to burp ITAB
    def getTabCaption(self):
        return "PyCript"


    # Returning the UI to the extension tab - Returning the new taB insite the extension tab
    def getUiComponent(self):
        return self.tabbedPane    

  
    
    # Auto Encrypt the request with IHttprequest listner
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            toolname = self.callbacks.getToolName(toolFlag)
            if toolname in self.tooltypelist and self.callbacks.isInScope(self.helpers.analyzeRequest(messageInfo).getUrl()):
                request = self.helpers.analyzeRequest(messageInfo)
                currentreq = messageInfo.getRequest()
                messageInfo.setRequest(EncryptRequest(self,currentreq,request))


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
                del self.tooltypelist[:]
            else:
                self.Autoencryptonoffbutton.setEnabled(True)
                
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
            del self.tooltypelist[:]
            self.Autoencryptonoffbutton.setEnabled(False)
            self.Autoencryptonoffbutton.setSelected(False)
        

    # Create the Menu for the extension
    def createMenuItems(self,invocation):
        menu_list = []

        menu_list.append(JMenuItem("Decrypt String", None,actionPerformed=lambda x, inv=invocation: self.decryptstring(inv)))
        menu_list.append(JMenuItem("Encrypt String", None,actionPerformed=lambda x, inv=invocation: self.encryptstring(inv)))
        #menu_list.append(JMenuItem("Decrypt Request", None,actionPerformed=lambda x, inv=invocation: self.decryptrequest(inv)))
        menu_list.append(JMenuItem("Decrypt Request", None,actionPerformed=lambda x, inv=invocation: Thread(target=self.decrypt_request_from_menu, args=(inv,)).start()))

       
      
        return menu_list


    # Decrypt the selected Request from Menu and Store the Decrypted Request in the Decrypted Request Table
    def decrypt_request_from_menu(self,invocation):
        if not str(self.selectedrequesttpye) == "None":
            reqRes = invocation.getSelectedMessages()
            for items in reqRes:
                
                req = self.helpers.analyzeRequest(items)
                self.method = req.getMethod()
                self.url = items.getUrl()
                
                self.responseinbytes = items.getResponse()
                self.responseinst = self.helpers.bytesToString(self.responseinbytes)
               
                currentreq = items.getRequest()
                self.decryptedrequest = DecryptRequest(self,currentreq,req)
                rowss = self.logTable.getRowCount()
                self.sr2 = str((rowss + 1))
                httpservice = items.getHttpService()
               

                self._lock.acquire()
                row = len(self._log)

                #self.url = self.helpers.analyzeRequest(self.decryptedrequest).getUrl()
               
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

            if self.selectedrequst:
                if not self.encryptionfilepath == "None":
                    encpath = self.encryptionfilepath
                elif not self.responseencryptionfilepath == "None":
                    encpath = self.responseencryptionfilepath
            else:
                if not self.responseencryptionfilepath == "None":
                    encpath = self.responseencryptionfilepath
                elif not self.encryptionfilepath == "None":
                    encpath = self.encryptionfilepath



            text = self.helpers.bytesToString(message_bytes)
            query = text[self.selection[0]:self.selection[1]]
            output = StringCrypto(self,encpath,query,http_request_response)
            encryptedstring = output.encrypt_string()
            
        
        
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


            if self.selectedrequst:
                if not self.decryptionfilepath == "None":
                    encpath = self.decryptionfilepath
                elif not self.responsedecryptionfilepath == "None":
                    encpath = self.responsedecryptionfilepath
            else:
                if not self.responsedecryptionfilepath == "None":
                    encpath = self.responsedecryptionfilepath
                elif not self.decryptionfilepath == "None":
                    encpath = self.decryptionfilepath

            text = self.helpers.bytesToString(message_bytes)
            query = text[self.selection[0]:self.selection[1]]
            output = StringCrypto(self,encpath,query,http_request_response)
            decryptedstring = output.decrypt_string()
           
        
        
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

    def clearerrortext(self,event):
        errorlogtextbox.setText("")

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
       

class RequestTabFactory(IMessageEditorTabFactory):
    def __init__(self, extender):
        self.extender = extender
        self.callbacks = self.extender.callbacks
    def createNewInstance(self, controller, editable):
        return CriptInputTab(self.extender, controller, editable)

class ResponseTabFactory(IMessageEditorTabFactory):
    def __init__(self, extender):
        self.extender = extender
        self.callbacks = self.extender.callbacks
    def createNewInstance(self, controller, editable):
        return ResponeCriptInputTab(self.extender, controller, editable)


