package io.alapierre.crypto.dss;

import eu.europa.esig.dss.token.PasswordInputCallback;
import lombok.SneakyThrows;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.11.20
 */
public class StdinPasswordInputCallback implements PasswordInputCallback {

    @SneakyThrows
    @Override
    public char[] getPassword() {
        System.out.println("Provide card PIT:");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        return br.readLine().toCharArray();
    }
}
