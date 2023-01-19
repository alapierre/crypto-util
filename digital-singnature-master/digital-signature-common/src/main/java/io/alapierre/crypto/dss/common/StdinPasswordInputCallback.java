package io.alapierre.crypto.dss.common;

import eu.europa.esig.dss.token.PasswordInputCallback;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.experimental.Tolerate;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.11.20
 */
@RequiredArgsConstructor
public class StdinPasswordInputCallback implements PasswordInputCallback {

    private final String message;
    private final String warningMessage;

    @Tolerate
    public StdinPasswordInputCallback() {
        this("Wprowadź PIN do karty", "Wpisywane znaki będą widoczne na konsoli!");
    }

    @SneakyThrows
    @Override
    public char[] getPassword() {
        System.out.println(message);

        Console console = System.console();
        if (console != null) {
            return console.readPassword("PIN: ");
        } else {
            System.err.println(warningMessage);
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            return br.readLine().toCharArray();
        }
    }
}
