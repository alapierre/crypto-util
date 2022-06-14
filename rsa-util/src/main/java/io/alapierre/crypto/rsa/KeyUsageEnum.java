package io.alapierre.crypto.rsa;

import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2018.08.27
 */
public enum KeyUsageEnum {

    SIGN(new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature)),
    ENCRYPT(new KeyUsage(KeyUsage.dataEncipherment)),
    SIGN_ENCRYPT(new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.dataEncipherment));

    KeyUsageEnum(KeyUsage keyUsage) {
        this.keyUsage = keyUsage;
    }

    private final KeyUsage keyUsage;

    public KeyUsage getKeyUsage() {
        return keyUsage;
    }

}
