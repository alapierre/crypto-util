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
