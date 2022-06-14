package io.alapierre.crypto.rsa;

import lombok.val;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.*;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.06.13
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RsaUtilTest {

    @BeforeAll
    void init() {
        RsaUtil.initBouncyCastleProvider();
    }

    @Test
    void testKeyGeneration() throws Exception {

        KeyPair keyPair = RsaUtil.generateKeyPair(4094);

        Assertions.assertNotNull(keyPair.getPrivate());
        Assertions.assertNotNull(keyPair.getPublic());

        RsaUtil.savePem(keyPair.getPrivate(), "alamakota".toCharArray(),
                Files.newOutputStream(createTmpFile("key_test", ".pem").toPath()));

    }

    @Test
    void generateCSR() throws Exception {

        KeyPair keyPair = RsaUtil.generateKeyPair(4094);

        PKCS10CertificationRequest csr = RsaUtil.generateCSR("CN=Adrian Lapierre, OU=Java, O=ITrust sp. z o.o., C=PL, emailAddress=al@alapierre.io",
                KeyUsageEnum.SIGN_ENCRYPT,
                keyPair);

        RsaUtil.savePem(csr, Files.newOutputStream(createTmpFile("csr", ".csr").toPath()));

        RsaUtil.savePem(keyPair.getPrivate(), "alamakota".toCharArray(), Files.newOutputStream(createTmpFile("id_key", ".pem").toPath()));
        // klucza publicznego nie da się wyświetlić w linux, ale można go zaimportować co XCA
        RsaUtil.savePem(keyPair.getPublic(), Files.newOutputStream(createTmpFile("public", ".pem").toPath()));
    }

    @Test
    void signCSR() throws Exception {

        KeyPair caKey = RsaUtil.loadPrivateKey(new FileReader("src/main/resources/Digital_Signature_CA_PK.pem"));

        val cert = RsaUtil.loadPemCert(new FileReader("src/main/resources/Digital_Signature_CA.crt"));
        val caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

        KeyPair keyPair = RsaUtil.generateKeyPair(4094);

        PKCS10CertificationRequest csr = RsaUtil.generateCSR("CN=Adrian Lapierre, OU=Java, O=ITrust sp. z o.o., C=PL, emailAddress=al@alapierre.io",
                KeyUsageEnum.SIGN_ENCRYPT,
                keyPair);

        LocalDate dateTo = LocalDate.now().plusYears(1);

        val signed = RsaUtil.createCertificate(
                csr,
                keyPair.getPublic(),
                caCert,
                caKey.getPrivate(),
                new Date(),
                java.sql.Date.valueOf(dateTo));

        JcaPEMWriter pemWriter = new JcaPEMWriter(new PrintWriter(System.out));
        pemWriter.writeObject(signed);
        pemWriter.close();
    }

    private File createTmpFile(String prefix, String suffix) throws IOException {
        File f = File.createTempFile(prefix, suffix);
        System.out.println(f.getAbsolutePath());
        return f;
    }

}
