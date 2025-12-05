package com.pycript.EncDec;

import java.io.*;
import java.nio.file.*;
import java.util.Random;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.ImmutablePair;
import com.pycript.ui.LogTab;

public class TempFile {

    private static final String PYCRIPT_DIR;
    private static final byte[] BODY_END_MARKER = "\n--BODY_END--\n".getBytes();

    static {
        String userHome = System.getProperty("user.home");
        PYCRIPT_DIR = userHome + File.separator + ".pycript";
        createTempDir();
    }

    public static Pair<byte[], String> parseTempFileOutput(byte[] originalData, String originalHeader, String tempFilePath) {
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get(tempFilePath));

            LogTab logTab = LogTab.getInstance();
            if (logTab != null && logTab.isLoggingEnabled()) {
                logTab.appendLog(new String(fileContent));
            }

            int markerIndex = indexOf(fileContent, BODY_END_MARKER);

            byte[] bodyData;
            String headerData;

            if (markerIndex != -1) {
                bodyData = new byte[markerIndex];
                System.arraycopy(fileContent, 0, bodyData, 0, markerIndex);

                int headerStart = markerIndex + BODY_END_MARKER.length;
                if (headerStart < fileContent.length) {
                    byte[] headerBytes = new byte[fileContent.length - headerStart];
                    System.arraycopy(fileContent, headerStart, headerBytes, 0, headerBytes.length);
                    String extractedHeader = new String(headerBytes).trim();
                    headerData = extractedHeader.isEmpty() ? originalHeader : extractedHeader;
                } else {
                    headerData = originalHeader;
                }
            } else {
                bodyData = fileContent;
                headerData = originalHeader;
            }

            return new ImmutablePair<>(bodyData, headerData);

        } catch (IOException e) {
            return new ImmutablePair<>(originalData, originalHeader);
        }
    }

    public static String createTempFile(byte[] data, String headerValue) throws IOException {
        // #20
        String randomFileName = generateRandomFileName(12);
        String filePath = PYCRIPT_DIR + File.separator + randomFileName;

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);

            fos.write(BODY_END_MARKER);

            if (headerValue != null && !headerValue.isEmpty()) {
                fos.write(headerValue.getBytes("UTF-8"));
            }
        }

        return filePath;
    }

    public static void createTempDir() {
        File dir = new File(PYCRIPT_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    public static void deleteTempFolder() {
        File dir = new File(PYCRIPT_DIR);
        if (dir.exists()) {
            deleteDirectory(dir);
        }
    }

    private static void deleteDirectory(File directory) {
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDirectory(file);
                } else {
                    file.delete();
                }
            }
        }
        directory.delete();
    }

    private static String generateRandomFileName(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private static int indexOf(byte[] array, byte[] pattern) {
        for (int i = 0; i <= array.length - pattern.length; i++) {
            boolean found = true;
            for (int j = 0; j < pattern.length; j++) {
                if (array[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return -1;
    }
}
