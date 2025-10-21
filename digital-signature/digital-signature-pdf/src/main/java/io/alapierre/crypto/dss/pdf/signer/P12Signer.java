package io.alapierre.crypto.dss.pdf.signer;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.val;

import java.io.InputStream;
import java.security.KeyStore;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.02.13
 */
@RequiredArgsConstructor
public class P12Signer extends Signer {

    private final KeyStore.PasswordProtection passwordProtection;
    private final InputStream signatureToken;

    public DSSDocument signDocument(@NonNull InputStream document) {
        val signingToken = new Pkcs12SignatureToken(signatureToken, passwordProtection);
        DSSDocument toSignDocument = new InMemoryDocument(document);
        return singPades(toSignDocument, signingToken);
    }

    public DSSDocument signDocument(byte[] document) {
        val signingToken = new Pkcs12SignatureToken(signatureToken, passwordProtection);
        DSSDocument toSignDocument = new InMemoryDocument(document);
        return singPades(toSignDocument, signingToken);
    }

}
