package io.alapierre.crypto.dss.signer;

import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import io.alapierre.crypto.misc.DllUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import static io.alapierre.crypto.misc.DllUtil.resolveDllAbsolutePathAndFileName;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.12.23
 */
@Slf4j
@RequiredArgsConstructor
public class CardSigner extends AbstractSigner {

    private final String relativePathToDll;
    private final String dllName;
    private final int slot;
    private final PasswordInputCallback passwordInputCallback;

    @Override
    protected @NotNull SignatureTokenConnection prepareToken() {
        DllUtil.DllInfo dllInfo = resolveDllAbsolutePathAndFileName(relativePathToDll, dllName);
        return new Pkcs11SignatureToken(dllInfo.getFullPath(), passwordInputCallback, slot);
    }
}
