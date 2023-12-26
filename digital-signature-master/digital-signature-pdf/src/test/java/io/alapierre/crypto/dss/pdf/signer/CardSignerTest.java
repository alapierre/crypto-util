package io.alapierre.crypto.dss.pdf.signer;

import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.PrefilledPasswordCallback;
import lombok.val;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.01.19
 */
class CardSignerTest {

    private final String pin = "";
    private final PasswordInputCallback callback = new PrefilledPasswordCallback(new KeyStore.PasswordProtection(pin.toCharArray()));

    @Test
    @Disabled
    void testSign() throws IOException {

        val signer = new CardSigner("/opt/proCertumSmartSign", "cryptoCertum3PKCS", 1, callback);

        val signed = signer.signDocument(new FileInputStream("src/test/resources/test.pdf"));
        signed.writeTo(new FileOutputStream("src/test/resources/signed.pdf"));

    }

}
