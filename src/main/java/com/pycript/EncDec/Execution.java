package com.pycript.EncDec;

import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;
import com.pycript.ui.LogTab;

public class Execution {

    public static Pair<byte[], String> executeCommand(String selectedLang, String path, byte[] data, String headerValue) {
        String tempFilePath = null;

        try {
            tempFilePath = TempFile.createTempFile(data, headerValue);

            List<String> command = new ArrayList<>();

            if (selectedLang != null && !selectedLang.isEmpty()) {
                command.add(selectedLang);
            }

            if (path.endsWith(".jar")) {
                command.add("-jar");
            }

            command.add(path);
            command.add("-d");
            command.add(tempFilePath);

            try {
                ProcessBuilder processBuilder = new ProcessBuilder(command);
                processBuilder.redirectErrorStream(false);

                LogTab logTab = LogTab.getInstance();
                if (logTab != null && logTab.isLoggingEnabled()) {
                    logTab.appendLog("\nroot@PyCript# " + String.join(" ", command));
                }

                Process process = processBuilder.start();

                StringBuilder output = new StringBuilder();
                StringBuilder errorOutput = new StringBuilder();

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                }

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        errorOutput.append(line).append("\n");
                    }
                }

                int exitCode = process.waitFor();

                if (logTab != null && logTab.isLoggingEnabled()) {
                    if (output.length() > 0) {
                        logTab.appendLog(output.toString().trim());
                    }
                    if (errorOutput.length() > 0) {
                        logTab.appendLog(errorOutput.toString().trim());
                    }
                }

                if (exitCode == 0) {
                    Pair<byte[], String> result = TempFile.parseTempFileOutput(data, headerValue, tempFilePath);

                    deleteTempFile(tempFilePath);

                    if (result.getLeft() != null && result.getLeft().length > 0) {
                        return result;
                    } else {
                        return null;
                    }
                } else {
                    deleteTempFile(tempFilePath);
                    return null;
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                deleteTempFile(tempFilePath);
                return null;
            }

        } catch (IOException e) {
            if (tempFilePath != null) {
                deleteTempFile(tempFilePath);
            }
            return null;
        } catch (Exception e) {
            if (tempFilePath != null) {
                deleteTempFile(tempFilePath);
            }
            return null;
        }
    }

    private static void deleteTempFile(String filePath) {
        try {
            Files.deleteIfExists(Paths.get(filePath));
        } catch (IOException e) {
        }
    }
}