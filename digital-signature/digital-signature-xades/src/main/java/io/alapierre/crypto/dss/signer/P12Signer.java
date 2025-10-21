package io.alapierre.crypto.dss.signer;

import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.12.23
 */
@Slf4j
@RequiredArgsConstructor
public class P12Signer extends AbstractSigner {

    private final KeyStore.PasswordProtection passwordProtection;
    private final File signatureToken;

    protected SignatureTokenConnection prepareToken() throws IOException {
        return new Pkcs12SignatureToken(signatureToken, passwordProtection);
    }

}
