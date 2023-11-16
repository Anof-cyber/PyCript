from javax.swing import JCheckBox, JTextArea, JScrollPane
from javax.swing import ScrollPaneConstants
from java.awt import Color, Font, Dimension
from javax.swing import BorderFactory

def create_third_tab_elements():
    global errorlogcheckbox, errorclear_button, errorlogtextbox, scroll_pane

    errorlogcheckbox = JCheckBox("Allow logging encryption/decryption command stderr and stdout ")
    
    errorlogtextbox = JTextArea(30, 110)  # Increased width
    errorlogtextbox.setBackground(Color(32, 32, 32))  # Dark gray background
    errorlogtextbox.setForeground(Color.WHITE)  # White text
    errorlogtextbox.setFont(Font("Consolas", Font.PLAIN, 14))  # Increased font size
    errorlogtextbox.setLineWrap(True)
    errorlogtextbox.setWrapStyleWord(False)
    scroll_pane = JScrollPane(errorlogtextbox)
    scroll_pane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS)
    scroll_pane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
    scroll_pane.setMaximumSize(Dimension(scroll_pane.getPreferredSize().width + 20, scroll_pane.getPreferredSize().height))  # Increased width
    scroll_pane.setBorder(BorderFactory.createEmptyBorder())  # Remove the border

    return errorlogcheckbox, scroll_pane, errorlogtextbox



def logerrors(new_data):
    if errorlogcheckbox.isSelected():
        errorlogtextbox.append(new_data + "\n")