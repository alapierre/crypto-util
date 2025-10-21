package io.alapierre.crypto.cipher;

import lombok.val;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static io.alapierre.crypto.cipher.AesCipher.getKeyFromPassword;
import static io.alapierre.crypto.cipher.IvUtil.*;


/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.22
 */
public class AesCipherTest {

    public static final String PLAIN_TEXT = "Ala ma kota, a kot ma Alę";

    @Test
    public void encrypt() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        val iv = generateRandomIv();
        System.out.println(ivToString(iv));

        val encrypted = AesCipher.encrypt(PLAIN_TEXT,
                getKeyFromPassword("secret", "5674321"),
                iv);

        System.out.println(encrypted);
        Assertions.assertNotNull(encrypted);
    }

    @Test
    public void decrypt() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        val secretText = "YY9xJB4+cQpCaBX2PDsoT5VZplf+asVpHrKiOfsdJp0=";
        val iv = "Fjk66YbVnH3bOn0aydM4fw==";

        val res = AesCipher.decrypt(secretText, getKeyFromPassword("secret", "5674321"), createIv(iv));

        System.out.println(res);
        Assertions.assertNotNull(res);
        Assertions.assertEquals(PLAIN_TEXT, res);
    }
}
