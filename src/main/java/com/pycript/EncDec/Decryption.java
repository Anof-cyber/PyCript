package com.pycript.encdec;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.ImmutablePair;

public class Decryption {

    public static Pair<String, String> Parameterdecrypt(String selectedLang, String decryptionPath, String body, String headersStr) {
        System.out.println("Decryption started...");
        System.out.println("Selected Language: " + selectedLang);
        System.out.println("Decryption Path: " + decryptionPath);

        String decryptedValue = "Decrypted: " + body; // Simulate decryption
        String updatedHeader = headersStr + "\r\nX-Decrypted: true"; // Add a custom header

        System.out.println("Decrypted Value: " + decryptedValue);
        System.out.println("Updated Header: " + updatedHeader);

        // Use ImmutablePair to return the values
        return new ImmutablePair<>(decryptedValue, updatedHeader);
    }
}
