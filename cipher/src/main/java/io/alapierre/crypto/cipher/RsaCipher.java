package io.alapierre.crypto.cipher;

import io.alapierre.io.IOUtils;
import lombok.val;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.07
 */
public class RsaCipher {

    private RsaCipher() {}

    /**
     * Reads public key in binary format (DER) from file
     *
     * @param publicKeyFile PublicKey file in binary format
     * @return PublicKey instance
     */
    public static PublicKey publicKey(File publicKeyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        try (FileInputStream is = new FileInputStream(publicKeyFile)) {
            return publicKey(is);
        }
    }

    /**
     * Reads public key from binary format (DER) from stream
     *
     * @param is PublicKey in binary format
     * @return PublicKey instance
     */
    public static PublicKey publicKey(InputStream is) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        return publicKey(IOUtils.toByteArray(is));
    }

    /**
     * Reads public key from binary format (DER)
     *
     * @param publicKeyBytes PublicKey in binary format
     * @return PublicKey instance
     * @throws InvalidKeySpecException if key is invalid
     * @throws NoSuchAlgorithmException if RSA algorithm not found
     */
    public static PublicKey publicKey(byte[] publicKeyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        val x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        val keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    /**
     * Load PublicKey in PEM format
     *
     * @param file PublicKey file
     * @return RSAPublicKey instance
     * @throws IOException if reading file problem occurs
     */
    public static RSAPublicKey publicKeyFromPem(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
        }
    }

    /**
     * Loads encrypted private key in PEM format
     *
     * @param privateKeyFile private key file in PEM
     * @throws FileNotFoundException if problem with reading private key file
     * @return read PrivateKey
     */
    public static PrivateKey loadPrivateKey(File privateKeyFile, char[] password) throws IOException {

        try (FileReader keyReader = new FileReader(privateKeyFile);
             PEMParser pemParser = new PEMParser(keyReader)) {

            Object object = pemParser.readObject();

            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password);

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            KeyPair kp;
            if (object instanceof PEMEncryptedKeyPair) {
                kp = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
            } else {
                PEMKeyPair ukp = (PEMKeyPair) object;
                kp = converter.getKeyPair(ukp);
            }
            return kp.getPrivate();
        }
    }

    /**
     * Encrypts provided plain text message by RSA algorithm, and provide Base64 encoded string
     *
     * @param plainText text to encrypt
     * @return encrypted text Base64 encoded
     */
    @NotNull
    public static String encode(@NotNull String plainText, PublicKey publicKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        val message = plainText.getBytes();

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        val encrypted = cipher.doFinal(message);

        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts RSA encrypted message from Base64 encoded string
     *
     * @param encryptedTextBaseEncoded secret message Base64 encoded
     * @return encrypted text
     */
    @NotNull
    public static String decode(@NotNull String encryptedTextBaseEncoded, PrivateKey privateKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        val encryptedText = Base64.getDecoder().decode(encryptedTextBaseEncoded);

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        val plainText = cipher.doFinal(encryptedText);
        return new String(plainText);
    }

}
