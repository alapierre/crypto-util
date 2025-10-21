package io.alapierre.crypto.dss.pdf.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.jetbrains.annotations.NotNull;

import static io.alapierre.crypto.dss.common.KeyUtil.findValidKey;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.02.13
 */
public abstract class Signer {

    protected  @NotNull DSSDocument singPades(@NotNull DSSDocument toSignDocument, @NotNull SignatureTokenConnection signingToken) {
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
