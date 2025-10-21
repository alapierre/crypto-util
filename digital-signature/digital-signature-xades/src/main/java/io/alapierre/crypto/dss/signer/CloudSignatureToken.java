package io.alapierre.crypto.dss.signer;

import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.Collections;
import java.util.List;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 29.06.2024
 */
public class CloudSignatureToken extends AbstractSignatureTokenConnection {

    private final String apiEndpoint;
    private final String apiKey;

    public CloudSignatureToken(String apiEndpoint, String apiKey) {
        this.apiEndpoint = apiEndpoint;
        this.apiKey = apiKey;
    }

    @Override
    public void close() {
        // Close any connections if necessary
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() {
        // Implement method to retrieve keys from the cloud service
        // This might involve making an API call to list available keys
        return Collections.emptyList();
    }

    public byte[] sign(byte[] dataToSign, String keyId) {
        // Implement method to send the data to the cloud API and get the signature
        // Use your API key and endpoint to make an HTTP request
        // Handle the response and return the signed data
        return null;
    }

    // Generate hash of the document
    //Digest digest = new Digest(DigestAlgorithm.SHA256, Utils.digest(DigestAlgorithm.SHA256, document));
    // new SignatureValue(SignatureAlgorithm.RSA_SHA256, signedHash);
}
