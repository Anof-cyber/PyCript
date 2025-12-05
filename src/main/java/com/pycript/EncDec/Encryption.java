package com.pycript.EncDec;

import org.apache.commons.lang3.tuple.Pair;

public class Encryption {

    public static Pair<byte[], String> Parameterencrypt(String selectedLang, String path, byte[] data, String headersStr) {
        Pair<byte[], String> result = Execution.executeCommand(selectedLang, path, data, headersStr);

        if (result != null) {
            return result;
        } else {
            return org.apache.commons.lang3.tuple.ImmutablePair.of(data, headersStr);
        }
    }
}
