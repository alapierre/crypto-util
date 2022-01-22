package io.alapierre.crypto.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * More secure AES Cipher based on GCM algorithm. AES-GCM provides a much better security contract all around than AES-CBC
 * https://crypto.stackexchange.com/questions/57645/is-using-the-same-iv-in-aes-similar-to-not-using-an-iv-in-the-first-place/57648#57648
 *
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.22
 */
public class AesGCMCipher {

    public static final String GCM_ALGORITHM = "AES/GCM/NoPadding";
    public static final int GCM_TAG_LENGTH = 16;

    public static String encrypt(String plaintext, SecretKey key, IvParameterSpec iv) throws Exception {

        Cipher cipher = Cipher.getInstance(GCM_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv.getIV());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {

        Cipher cipher = Cipher.getInstance(GCM_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv.getIV());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decryptedText);
    }

}
