package io.alapierre.crypto.dss.signer;

import eu.europa.esig.dss.model.DSSDocument;
import org.junit.jupiter.api.BeforeAll;
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
class P12SignerTest {

    private final KeyStore.PasswordProtection pas = new KeyStore.PasswordProtection("123ewqasd".toCharArray());
    private P12Signer signer;
    private final File token = new File("src/test/resources/stamp.p12");

    @BeforeAll
    void init() {
        signer = new P12Signer(pas, token);
    }

    @Test
    void testSign() throws IOException {

        DSSDocument signedDocument = signer.sign(Paths.get("src/test/resources", "pit_11.xml").toFile());

        File outFile = Paths.get("src/test/resources", "signed2.xml").toFile();
        signedDocument.save(outFile.getAbsolutePath());

    }

}
