package com.pycript.ui;

import javax.swing.*;
import java.awt.*;

public class LogTab extends JPanel
{
    public LogTab()
    {
        super(new BorderLayout());
        JLabel label = new JLabel("Content for Log Tab");
        this.add(label, BorderLayout.CENTER);
    }
}
