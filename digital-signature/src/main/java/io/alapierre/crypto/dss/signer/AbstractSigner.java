package io.alapierre.crypto.dss.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.List;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.12.23
 */
@Slf4j
public abstract class AbstractSigner {

    protected abstract @NotNull SignatureTokenConnection prepareToken() throws IOException;

    public @NotNull DSSDocument signXades(@NotNull DSSDocument toSignDocument, @NotNull SignatureTokenConnection token) {

        DSSPrivateKeyEntry privateKey = findValidKey(token.getKeys());

        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(privateKey.getCertificate());

        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        XAdESService service = new XAdESService(commonCertificateVerifier);

        ToBeSigned toBeSigned = service.getDataToSign(toSignDocument, parameters);
        SignatureValue signatureValue = token.sign(toBeSigned, parameters.getDigestAlgorithm(), privateKey);

        return service.signDocument(toSignDocument, parameters, signatureValue);
    }

    public @NotNull DSSDocument sign(@NotNull File documentPath) throws IOException {
        DSSDocument toSignDocument = new FileDocument(documentPath);
        return prepareAndSign(toSignDocument);
    }

    public @NotNull DSSDocument sign(@NotNull InputStream document) throws IOException {
        DSSDocument toSignDocument = new InMemoryDocument(document);
        return prepareAndSign(toSignDocument);
    }

    @NotNull
    private DSSDocument prepareAndSign(DSSDocument toSignDocument) throws IOException {
        try (SignatureTokenConnection token = prepareToken()) {
            return signXades(toSignDocument, token);
        }
    }

    protected @NotNull DSSPrivateKeyEntry findValidKey(@NotNull List<DSSPrivateKeyEntry> keys) {

        Date now = new Date();

        for (DSSPrivateKeyEntry k : keys) {
            Date endDate = k.getCertificate().getNotAfter();
            Date startDate = k.getCertificate().getNotBefore();

            log.debug("sprawdzam certyfikat {} {}", startDate, endDate);

            if(isDayInRange(now, startDate, endDate)) return k;
        }

        throw new IllegalStateException("Brak ważnego certyfikatu");
    }

    protected boolean isDayInRange(@NotNull Date day, @NotNull Date from, @NotNull Date to) {
        return !(day.before(from) || day.after(to));
    }

}
