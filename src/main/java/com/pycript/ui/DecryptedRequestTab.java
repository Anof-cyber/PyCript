package com.pycript.ui;

import javax.swing.*;
import java.awt.*;

public class DecryptedRequestTab extends JPanel
{
    public DecryptedRequestTab()
    {
        super(new BorderLayout());
        JLabel label = new JLabel("Content for Decrypted Request Tab");
        this.add(label, BorderLayout.CENTER);
    }
}
