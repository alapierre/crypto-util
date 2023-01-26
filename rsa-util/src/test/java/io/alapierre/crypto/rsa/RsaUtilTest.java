package io.alapierre.crypto.rsa;

import lombok.Cleanup;
import lombok.val;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.KeyPair;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Date;

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

        Assertions.assertNotNull(csr);

        RsaUtil.savePem(csr, Files.newOutputStream(createTmpFile("csr", ".csr").toPath()));

        RsaUtil.savePem(keyPair.getPrivate(), "alamakota".toCharArray(), Files.newOutputStream(createTmpFile("id_key", ".pem").toPath()));
        // klucza publicznego nie da się wyświetlić w linux, ale można go zaimportować co XCA
        RsaUtil.savePem(keyPair.getPublic(), Files.newOutputStream(createTmpFile("public", ".pem").toPath()));
    }

    @Test
    void signCSR() throws Exception {

        val caKey = RsaUtil.loadPrivateKey(new FileReader("src/test/resources/Digital_Signature_CA_PK.pem"));

        val cert = RsaUtil.loadPemCert(new FileReader("src/test/resources/Digital_Signature_CA.crt"));
        val caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

        KeyPair keyPair = RsaUtil.generateKeyPair(4094);

        Assertions.assertNotNull(keyPair);

        PKCS10CertificationRequest csr = RsaUtil.generateCSR("CN=Adrian Lapierre, OU=Java, O=ITrust sp. z o.o., C=PL, emailAddress=al@alapierre.io",
                KeyUsageEnum.SIGN_ENCRYPT,
                keyPair);

        Assertions.assertNotNull(csr);

        LocalDate dateTo = LocalDate.now().plusYears(1);

        val signed = RsaUtil.createCertificate(
                csr,
                keyPair.getPublic(),
                caCert,
                caKey,
                new Date(),
                java.sql.Date.valueOf(dateTo));

        Assertions.assertNotNull(signed);

        @Cleanup JcaPEMWriter pemWriter = new JcaPEMWriter(new PrintWriter(System.out));
        pemWriter.writeObject(signed);

        val certChain = Arrays.asList(new X509CertificateHolder(signed.getEncoded()), cert);

        RsaUtil.packToPKCS12(createTmpFile("stamp", ".p12"), null, "123ewqasd".toCharArray(),
                keyPair.getPrivate(), certChain);
    }

    private File createTmpFile(String prefix, String suffix) throws IOException {
        File f = File.createTempFile(prefix, suffix);
        System.out.println(f.getAbsolutePath());
        return f;
    }

    @Test
    void decryptTest() {

    }

    @Test
    void signAndVerify() throws Exception {

        val pair = RsaUtil.generateKeyPair(2048);
        val message = "Ala ma kota".getBytes();
        val signature = RsaUtil.signMessage(message, pair.getPrivate());

        val result = RsaUtil.verifySignature(message, signature, pair.getPublic());
        System.out.println(result);

        Assertions.assertTrue(result, "Signature do not match");

    }

    @Test
    void signNotMatch() throws Exception {

        val pair = RsaUtil.generateKeyPair(2048);
        val message = "Ala ma kota".getBytes();
        val signature = RsaUtil.signMessage(message, pair.getPrivate());

        val result = RsaUtil.verifySignature("Ala ma kota1".getBytes(), signature, pair.getPublic());
        System.out.println(result);

        Assertions.assertFalse(result, "Signature do not match");

    }

}
