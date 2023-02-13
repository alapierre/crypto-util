package io.alapierre.crypto.dss.pdf.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.InputStream;
import java.security.KeyStore;

import static io.alapierre.crypto.dss.common.KeyUtil.findValidKey;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.02.13
 */
@RequiredArgsConstructor
public class P12Signer extends Signer {

    private final KeyStore.PasswordProtection passwordProtection;
    private final InputStream signatureToken;

    public @NotNull DSSDocument signDocument(@NonNull InputStream document) {

        val signingToken = new Pkcs12SignatureToken(signatureToken, passwordProtection);
        DSSDocument toSignDocument = new InMemoryDocument(document);

        return singPades(toSignDocument, signingToken);
    }

}
