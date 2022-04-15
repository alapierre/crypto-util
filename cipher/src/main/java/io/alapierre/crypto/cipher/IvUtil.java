package io.alapierre.crypto.cipher;

import lombok.val;
import org.jetbrains.annotations.NotNull;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.22
 */
public class IvUtil {

    private static final SecureRandom secureRandom = new SecureRandom();

    @NotNull
    public static IvParameterSpec generateRandomIv() {
        return generateRandomIv(16);
    }

    @NotNull
    public static IvParameterSpec generateRandomIv(int len) {
        byte[] iv = new byte[len];
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    @NotNull
    public static String ivToString(@NotNull IvParameterSpec iv) {
        return Base64.getEncoder().encodeToString(iv.getIV());
    }

    @NotNull
    public static IvParameterSpec createIv(@NotNull String base64encodedString) {
        val iv = Base64.getDecoder().decode(base64encodedString);
        return new IvParameterSpec(iv);
    }

}
