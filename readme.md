[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=alapierre_crypto-util&metric=alert_status)](https://sonarcloud.io/dashboard?id=alapierre_crypto-util)
[![Renovate enabled](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com/)
[![Maven Central](http://img.shields.io/maven-central/v/io.alapierre.crypto/crypto-util)](https://search.maven.org/artifact/io.alapierre.crypto/crypto-util)

# Common Cryptography utils

````java

File tokenFile = new File("token.p12");
KeyStore.PasswordProtection pas = new KeyStore.PasswordProtection("_____token_password_____".toCharArray());;

val signer = new P12Signer(pas, tokenFile);

ByteArrayInputStream is = new ByteArrayInputStream(toSigned);
DSSDocument signedDocument = signer.sign(is);

ByteArrayOutputStream signed = new ByteArrayOutputStream();
signedDocument.writeTo(signed);

````
