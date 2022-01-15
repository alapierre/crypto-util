package io.alapierre.crypto.cipher;

import io.alapierre.io.IOUtils;
import lombok.SneakyThrows;
import lombok.val;
import org.jetbrains.annotations.NotNull;


import javax.crypto.Cipher;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.07
 */
public class RsaCipher {

    private final byte[] publicKey;

    @SneakyThrows
    public RsaCipher(@NotNull InputStream publicKeyStream) {
        publicKey = IOUtils.toByteArray(publicKeyStream);
    }

    /**
     * Encrypts provided plain text message by RSA algorithm, and provide Base64 encoded string
     *
     * @param plainText text to encrypt
     * @return encrypted text Base64 encoded
     */
    @SneakyThrows
    @NotNull
    public String encode(@NotNull String plainText) {

        val x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        val keyFactory = KeyFactory.getInstance("RSA");
        val publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

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
    @SneakyThrows
    @NotNull
    public String decode(@NotNull String encryptedTextBaseEncoded) {

        val x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        val keyFactory = KeyFactory.getInstance("RSA");
        val publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

        val encryptedText = Base64.getDecoder().decode(encryptedTextBaseEncoded);

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        val plainText = cipher.doFinal(encryptedText);
        return new String(plainText);
    }

}
