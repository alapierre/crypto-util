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
import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import io.alapierre.crypto.dss.common.misc.DllUtil;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jetbrains.annotations.NotNull;

import java.io.InputStream;


import static io.alapierre.crypto.dss.common.KeyUtil.*;
import static io.alapierre.crypto.dss.common.misc.DllUtil.resolveDllAbsolutePathAndFileName;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.01.19
 */
@Slf4j
@RequiredArgsConstructor
public class CardSigner {

    private final String relativePathToDll;
    private final String dllName;
    private final int slot;
    private final PasswordInputCallback passwordInputCallback;

    public @NotNull DSSDocument signDocument(@NonNull InputStream document) {

        DSSDocument toSignDocument = new InMemoryDocument(document);

        DllUtil.DllInfo dllInfo = resolveDllAbsolutePathAndFileName(relativePathToDll, dllName);

        try (val signingToken = new Pkcs11SignatureToken(dllInfo.getFullPath(), passwordInputCallback, slot)) {
            DSSPrivateKeyEntry privateKey = findValidKey(signingToken.getKeys());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(commonCertificateVerifier);

            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(privateKey.getCertificate());

            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            return service.signDocument(toSignDocument, parameters, signatureValue);

        }
    }
}
