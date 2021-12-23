package io.alapierre.crypto.dss.signer;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.PrefilledPasswordCallback;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.12.23
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CardSignerTest {

    private final String pin = "";
    private final PasswordInputCallback callback = new PrefilledPasswordCallback(new KeyStore.PasswordProtection(pin.toCharArray()));

    private CardSigner signer;

    @BeforeAll
    void init() {
        signer = new CardSigner("/opt/proCertumSmartSign", "cryptoCertum3PKCS", 1, callback);
    }

    @Test
    @Disabled
    void testSign() throws IOException {
        DSSDocument signedDocument = signer.sign(Paths.get("src/test/resources", "pit_11.xml").toFile());
        File outFile = Paths.get("src/test/resources", "signed.xml").toFile();
        signedDocument.save(outFile.getAbsolutePath());
    }

}
