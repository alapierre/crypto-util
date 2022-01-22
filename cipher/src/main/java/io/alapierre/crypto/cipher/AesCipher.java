package io.alapierre.crypto.cipher;

import lombok.val;
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Less secure AES Cipher based on CBC algorithm
 *
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.07
 */
public class AesCipher {

    //CBC (Cipher Block Chaining)
    public static final String CBC_ALGORITHM = "AES/CBC/PKCS5Padding";

    @NotNull
    public static String encrypt(@NotNull String input, @NotNull SecretKey key, @NotNull IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(CBC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    @NotNull
    public static String decrypt(@NotNull String cipherText, @NotNull SecretKey key, @NotNull IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(CBC_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    @NotNull
    public static SecretKey getKeyFromPassword(@NotNull String password, @NotNull String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

}
