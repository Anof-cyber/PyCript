package com.pycript.ui;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.EditorOptions;

public class DecryptedRequestTab extends JPanel
{
    private final DecryptedRequestTableModel tableModel;
    private final JTable table;
    private RawEditor requestViewer;
    private RawEditor responseViewer;
    private static DecryptedRequestTab instance;

    public DecryptedRequestTab(MontoyaApi api)
    {
        super(new BorderLayout());
        instance = this;

        tableModel = new DecryptedRequestTableModel();
        table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JScrollPane tableScrollPane = new JScrollPane(table);
        tableScrollPane.setPreferredSize(new Dimension(0, 200));

        requestViewer = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);

        JTabbedPane messageViewerPane = new JTabbedPane();
        messageViewerPane.addTab("Request", requestViewer.uiComponent());
        messageViewerPane.addTab("Response", responseViewer.uiComponent());

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(tableScrollPane);
        splitPane.setBottomComponent(messageViewerPane);
        splitPane.setDividerLocation(200);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(selectedRow);
                    DecryptedRequestEntry entry = tableModel.getEntry(modelRow);
                    if (entry != null) {
                        requestViewer.setContents(entry.getDecryptedRequest().toByteArray());
                        if (entry.getResponse() != null) {
                            responseViewer.setContents(entry.getResponse().toByteArray());
                        } else {
                            responseViewer.setContents(ByteArray.byteArray("No Response"));
                        }
                    }
                }
            }
        });

        this.add(splitPane, BorderLayout.CENTER);
    }

    public static DecryptedRequestTab getInstance() {
        return instance;
    }

    public void addEntry(String method, String url, HttpRequest decryptedRequest, HttpResponse response) {
        tableModel.addEntry(new DecryptedRequestEntry(method, url, decryptedRequest, response));
    }

    private static class DecryptedRequestTableModel extends AbstractTableModel
    {
        private final List<DecryptedRequestEntry> entries = new ArrayList<>();
        private final String[] columnNames = {"#", "Method", "URL"};

        @Override
        public int getRowCount() {
            return entries.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            DecryptedRequestEntry entry = entries.get(rowIndex);
            switch (columnIndex) {
                case 0: return rowIndex + 1;
                case 1: return entry.getMethod();
                case 2: return entry.getUrl();
                default: return "";
            }
        }

        public void addEntry(DecryptedRequestEntry entry) {
            int row = entries.size();
            entries.add(entry);
            fireTableRowsInserted(row, row);
        }

        public DecryptedRequestEntry getEntry(int row) {
            if (row >= 0 && row < entries.size()) {
                return entries.get(row);
            }
            return null;
        }
    }

    private static class DecryptedRequestEntry
    {
        private final String method;
        private final String url;
        private final HttpRequest decryptedRequest;
        private final HttpResponse response;

        public DecryptedRequestEntry(String method, String url, HttpRequest decryptedRequest, HttpResponse response) {
            this.method = method;
            this.url = url;
            this.decryptedRequest = decryptedRequest;
            this.response = response;
        }

        public String getMethod() {
            return method;
        }

        public String getUrl() {
            return url;
        }

        public HttpRequest getDecryptedRequest() {
            return decryptedRequest;
        }

        public HttpResponse getResponse() {
            return response;
        }
    }
}
