[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=alapierre_crypto-util&metric=alert_status)](https://sonarcloud.io/dashboard?id=alapierre_crypto-util)
[![Renovate enabled](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com/)
[![Maven Central](http://img.shields.io/maven-central/v/io.alapierre.crypto/crypto-util)](https://search.maven.org/artifact/io.alapierre.crypto/crypto-util)

# Common Cryptography utils

## Digitally sign given dokument with Xades signature 

````java

File tokenFile = new File("token.p12");
KeyStore.PasswordProtection pas = new KeyStore.PasswordProtection("_____token_password_____".toCharArray());;

val signer = new P12Signer(pas, tokenFile);

ByteArrayInputStream is = new ByteArrayInputStream(toSigned);
DSSDocument signedDocument = signer.sign(is);

ByteArrayOutputStream signed = new ByteArrayOutputStream();
signedDocument.writeTo(signed);

````

## Prepare RSA CSR 

````java
KeyPair keyPair = RsaUtil.generateKeyPair(4094);

PKCS10CertificationRequest csr = RsaUtil.generateCSR("CN=Adrian Lapierre, OU=Java, O=ITrust sp. z o.o., C=PL, emailAddress=al@alapierre.io",
        KeyUsageEnum.SIGN_ENCRYPT,
        keyPair);

RsaUtil.savePem(csr, Files.newOutputStream(createTmpFile("csr", ".csr").toPath()));
RsaUtil.savePem(keyPair.getPrivate(), "alamakota".toCharArray(), Files.newOutputStream(createTmpFile("id_key", ".pem").toPath()));
RsaUtil.savePem(keyPair.getPublic(), Files.newOutputStream(createTmpFile("public", ".pem").toPath()));

````

## Sign given CSR and pack into .p12 file

````java
val caKey = RsaUtil.loadPrivateKey(new FileReader("src/test/resources/Digital_Signature_CA_PK.pem"));
val cert = RsaUtil.loadPemCert(new FileReader("src/test/resources/Digital_Signature_CA.crt"));
val caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);

LocalDate dateTo = LocalDate.now().plusYears(1);

val signed = RsaUtil.createCertificate(
        csr,
        keyPair.getPublic(),
        caCert,
        caKey,
        new Date(),
        java.sql.Date.valueOf(dateTo));

val certChain = Arrays.asList(new X509CertificateHolder(signed.getEncoded()), cert);

RsaUtil.packToPKCS12(createTmpFile("stamp", ".p12"), null, "123ewqasd".toCharArray(),
        keyPair.getPrivate(), certChain);

````

## Generate self-signed CA with no key encryption

````shell
openssl req -x509 \
-sha256 -days 9125 \
-nodes \
-newkey rsa:2048 \
-subj "/CN=My test root CA/C=FR/L=St. Tropez/O=My corp" \
-keyout Digital_Signature_CA_PK.pem -out Digital_Signature_CA.crt 
````
