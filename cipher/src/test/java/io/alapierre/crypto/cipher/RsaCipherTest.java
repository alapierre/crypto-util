package io.alapierre.crypto.cipher;

import lombok.val;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2022.01.22
 */
public class RsaCipherTest {

    public static final String PLAIN_TEXT_MESSAGE = "Ala ma kota, a kot ma Alę";

    @BeforeAll
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void loadTestPK() throws IOException {
        val pk = RsaCipher.loadPrivateKey(new File("src/test/resources/private.pem"), "secret".toCharArray());
        Assertions.assertNotNull(pk);
    }

    @Test
    public void loadPublicKey() throws IOException {
        val publicKey = RsaCipher.publicKeyFromPem(new File("src/test/resources/public.pem"));
        Assertions.assertNotNull(publicKey);
    }

    @Test
    public void loadPublicKeyInDerFormat() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        val publicKey = RsaCipher.publicKey(new File("src/test/resources/public.der"));
        Assertions.assertNotNull(publicKey);
    }

    @Test
    public void encryptWithDerPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        val publicKey = RsaCipher.publicKey(new File("src/test/resources/public.der"));
        val secret = RsaCipher.encode(PLAIN_TEXT_MESSAGE, publicKey);
        System.out.println(secret);
        Assertions.assertNotNull(secret);
    }

    @Test
    public void encryptTestFormFile() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        val publicKey = RsaCipher.publicKeyFromPem(new File("src/test/resources/public.pem"));
        val res = RsaCipher.encode(PLAIN_TEXT_MESSAGE, publicKey);

        System.out.println(res);

        Assertions.assertNotNull(res, "secret text should not be null");
    }

    @Test
    public void decryptTest() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        val pk = RsaCipher.loadPrivateKey(new File("src/test/resources/private.pem"), "secret".toCharArray());

        val secretText = "WifYHO1nNfkBgIpBQZM5PbwmzP3U3Lyw06U17qTJVqq1prUUwS6HeKFmT9+ElhTc25SSdrrUinUPWgLkckU66jK3NV7y" +
                "K2xDJ47B/n+GIOhBBlfpSvSywHzH1aKvlP+CXWxVV/L5bbWHsovtUiwbUohMTFHac+5ecTH5OXVxYOTjoTznpZDfX35f76rT4Sw02" +
                "Lk7JsmVKRhVDndutVKdyyKHkviM/LqOlW6oDpxE1l5Zad1bK6CV80XZOUC4uOrSOxFG1n1ijrIhUQ59CdgqoRFvQJLS9+D1USle73" +
                "mtF0jcsPpFyoTumnL8INSxj5e5Wboi60FL0PpdtXlc6Q+NTw==";

        val res = RsaCipher.decode(secretText, pk);

        System.out.println(res);
        Assertions.assertEquals(PLAIN_TEXT_MESSAGE, res);
    }

    @Test
    public void encryptTest() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        val res = RsaCipher.encode(PLAIN_TEXT_MESSAGE, publicKey);

        System.out.println(res);

        Assertions.assertNotNull(res, "secret text should not be null");
    }

}
