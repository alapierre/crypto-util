package io.alapierre.crypto.dss.signer;

import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import io.alapierre.crypto.misc.DllUtil;
import lombok.extern.slf4j.Slf4j;

import static io.alapierre.crypto.misc.DllUtil.resolveDllAbsolutePathAndFileName;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.12.23
 */
@Slf4j
public class CardSigner extends AbstractSigner {

    private final String relativePathToDll;
    private final String dllName;
    private final int slot;
    private final PasswordInputCallback passwordInputCallback;
    private final boolean useSlotIndex;

    public CardSigner(String relativePathToDll, String dllName, int slot, PasswordInputCallback passwordInputCallback) {
        this.relativePathToDll = relativePathToDll;
        this.dllName = dllName;
        this.slot = slot;
        this.passwordInputCallback = passwordInputCallback;
        this.useSlotIndex = false;
    }

    public CardSigner(String relativePathToDll, String dllName, int slot, boolean useSlotListIndex, PasswordInputCallback passwordInputCallback) {
        this.relativePathToDll = relativePathToDll;
        this.dllName = dllName;
        this.slot = slot;
        this.passwordInputCallback = passwordInputCallback;
        this.useSlotIndex = useSlotListIndex;
    }

    @Override
    protected SignatureTokenConnection prepareToken() {
        DllUtil.DllInfo dllInfo = resolveDllAbsolutePathAndFileName(relativePathToDll, dllName);

        if (!useSlotIndex) {
            return new Pkcs11SignatureToken(dllInfo.getFullPath(), passwordInputCallback, slot);
        } else {
            return new Pkcs11SignatureToken(dllInfo.getFullPath(), passwordInputCallback, -1, slot, null);
        }
    }
}
