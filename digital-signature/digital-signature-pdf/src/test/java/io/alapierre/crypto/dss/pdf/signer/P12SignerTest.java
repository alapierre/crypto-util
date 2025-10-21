package io.alapierre.crypto.dss.pdf.signer;

import lombok.val;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.02.13
 */
class P12SignerTest {

    @Test
    void signDocument() throws Exception {

        val pas = new KeyStore.PasswordProtection("123ewqasd".toCharArray());
        P12Signer signer = new P12Signer(pas, new FileInputStream(("src/test/resources/stamp.p12")));

        val signed = signer.signDocument(new FileInputStream("src/test/resources/test.pdf"));
        signed.writeTo(new FileOutputStream("src/test/resources/signed.pdf"));

    }
}
