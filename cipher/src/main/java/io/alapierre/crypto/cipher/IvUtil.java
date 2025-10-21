package io.alapierre.crypto.cipher;

import lombok.NonNull;
import lombok.val;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.22
 */
public class IvUtil {

    private static final SecureRandom secureRandom = new SecureRandom();


    public static IvParameterSpec generateRandomIv() {
        return generateRandomIv(16);
    }


    public static IvParameterSpec generateRandomIv(int len) {
        byte[] iv = new byte[len];
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }


    public static String ivToString(@NonNull IvParameterSpec iv) {
        return Base64.getEncoder().encodeToString(iv.getIV());
    }


    public static IvParameterSpec createIv(@NonNull String base64encodedString) {
        val iv = Base64.getDecoder().decode(base64encodedString);
        return new IvParameterSpec(iv);
    }

}
