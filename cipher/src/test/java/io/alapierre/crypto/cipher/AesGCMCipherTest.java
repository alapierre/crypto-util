package io.alapierre.crypto.cipher;

import lombok.val;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static io.alapierre.crypto.cipher.AesCipher.getKeyFromPassword;
import static io.alapierre.crypto.cipher.IvUtil.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.22
 */
class AesGCMCipherTest {

    public static final String PLAIN_TEXT = "Ala ma kota, a kot ma Alę";

    @Test
    void encrypt() throws Exception {

        val iv = generateRandomIv();
        System.out.println(ivToString(iv));

        val encrypted = AesGCMCipher.encrypt(PLAIN_TEXT, getKeyFromPassword("secret", "5674321"), iv);

        System.out.println(encrypted);
        Assertions.assertNotNull(encrypted);
    }

    @Test
    void decrypt() throws Exception {

        val secretText = "lb3c+rPoZCdFSyz7dNQs5dcg1ByKtfFVEe9eKLjppol57wVRUlzbmi32";
        val iv = "d6rH87FEeATQ6eJkKi693A==";

        val res = AesGCMCipher.decrypt(secretText, getKeyFromPassword("secret", "5674321"), createIv(iv));

        System.out.println(res);
        Assertions.assertNotNull(res);
        Assertions.assertEquals(PLAIN_TEXT, res);
    }
}
