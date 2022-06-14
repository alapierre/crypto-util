package io.alapierre.crypto.rsa;

import lombok.Cleanup;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2018.08.27
 */
@SuppressWarnings("unused")
@Slf4j
public class RsaUtil {

    /**
     * Initialize BC provider, should be run one on application startup
     */
    public static void initBouncyCastleProvider() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Generate RSA key pair on given size
     *
     * @param keySize key size in bits
     * @return KeyPair
     * @throws NoSuchProviderException when BC is not available and cannot be instanced
     * @throws NoSuchAlgorithmException when RAS algorithm is not available
     */
    public static KeyPair generateKeyPair(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(keySize, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    /**
     * Generate CSR based on given certificate subject, key usage and keyPair
     *
     * @param subject certificate subject
     * @param usage key usage enum
     * @param keyPair public and private key
     * @return PKCS10 Certification Request
     * @throws OperatorCreationException  on CSR creation error
     * @throws IOException on IO operation error
     */
    public static PKCS10CertificationRequest generateCSR(@NonNull String subject, @NonNull KeyUsageEnum usage, @NonNull KeyPair keyPair) throws OperatorCreationException, IOException {

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(subject),
                keyPair.getPublic());

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");

        ContentSigner signer = csBuilder.build(keyPair.getPrivate());

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.keyUsage, false, usage.getKeyUsage());

        p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        return p10Builder.build(signer);
    }

    /**
     * Save CSR into PEM format
     *
     * @param csr CSR
     * @param out OutputStream
     * @throws IOException on IO operation error
     */
    public static void savePem(@NonNull PKCS10CertificationRequest csr, @NonNull OutputStream out) throws IOException {
        @Cleanup JcaPEMWriter pemWrt = new JcaPEMWriter(new OutputStreamWriter(out));
        pemWrt.writeObject(csr);
    }

    /**
     * Save Private Key into password-protected PEM format
     *
     * @param privateKey private key to save
     * @param passwd password for private key
     * @param out OutputStream
     * @throws IOException on IO operation error
     * @throws OperatorCreationException on JcaPKCS8Generator creation error
     */
    public static void savePem(@NonNull PrivateKey privateKey, char[] passwd, @NonNull OutputStream out) throws IOException, OperatorCreationException {

        @Cleanup JcaPEMWriter pemWrt = new JcaPEMWriter(new OutputStreamWriter(out));
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
        encryptorBuilder.setPassword(passwd);

        JcaPKCS8Generator gen = new JcaPKCS8Generator(privateKey,encryptorBuilder.build());
        pemWrt.writeObject(gen.generate());

    }

    /**
     * Save Public Key into PEM format
     *
     * @param publicKey public key to save
     * @param out OutputStream
     * @throws IOException on IO operation error
     */
    public static void savePem(@NonNull PublicKey publicKey, @NonNull OutputStream out) throws IOException {
        @Cleanup JcaPEMWriter pemWrt = new JcaPEMWriter(new OutputStreamWriter(out));
        pemWrt.writeObject(publicKey);
    }

    /**
     * Pack private key with certificate chain (X509CertificateHolder) into single PKCS12 password-protected file
     * @param outFile fole to store PKCS12
     * @param pkPass password for private Key
     * @param keystorePass password for PKCS12 file
     * @param privateKey private key
     * @param certChain certification chain
     * @throws KeyStoreException on problem with KeyStore creation
     * @throws CertificateException on problem with keystore creation
     * @throws NoSuchAlgorithmException on problem with keystore creation
     * @throws IOException on problem with keystore IO operations
     */
    public static void packToPKCS12(@NonNull File outFile, char[] pkPass, char[] keystorePass, @NonNull PrivateKey privateKey,
                                    @NonNull List<X509CertificateHolder> certChain)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        KeyStore outStore = KeyStore.getInstance("PKCS12");

        outStore.load(null, keystorePass);

        outStore.setKeyEntry("mykey", privateKey, pkPass, convertToX509Certificates(certChain));
        @Cleanup OutputStream outputStream = Files.newOutputStream(outFile.toPath());
        outStore.store(outputStream, keystorePass);
    }

    /**
     * Pack private key with certificate chain into single PKCS12 password-protected file
     * @param outFile fole to store PKCS12
     * @param pkPass password for private Key
     * @param keystorePass password for PKCS12 file
     * @param privateKey private key
     * @param certChain certification chain
     * @throws KeyStoreException on problem with KeyStore creation
     * @throws CertificateException on problem with keystore creation
     * @throws NoSuchAlgorithmException on problem with keystore creation
     * @throws IOException on problem with keystore IO operations
     */
    public static void packToPKCS12(@NonNull File outFile, char[] pkPass, char[] keystorePass, @NonNull PrivateKey privateKey,
                                    @NonNull X509Certificate[] certChain)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        KeyStore outStore = KeyStore.getInstance("PKCS12");

        outStore.load(null, keystorePass);

        outStore.setKeyEntry("mykey", privateKey, pkPass, certChain);
        @Cleanup OutputStream outputStream = Files.newOutputStream(outFile.toPath());
        outStore.store(outputStream, keystorePass);
    }

    /**
     * Convert X509CertificateHolder into X509Certificate
     * @param holder holder to convert
     * @return converted certificate or empty value
     */
    private static Optional<X509Certificate> convertToX509Certificates(@NonNull X509CertificateHolder holder) {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        try {
            return Optional.of(converter.getCertificate(holder));
        } catch (CertificateException e) {
            return Optional.empty();
        }
    }

    /**
     * Convert list of X509CertificateHolder into array of X509Certificate
     * @param certChain certs to convert
     * @return converted array
     */
    private static X509Certificate[] convertToX509Certificates(@NonNull List<X509CertificateHolder> certChain) {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

        return certChain.stream().map(it -> {
            try {
                return converter.getCertificate(it);
            } catch (CertificateException e) {
                log.warn("problem converting certificate " + e.getMessage());
                return null;
            }
        }).filter(Objects::nonNull).toArray(X509Certificate[]::new);
    }

    /**
     * Loads cert patch from P7 file
     *
     * @param p7bFile file to read
     * @return list of CertificateHolder
     * @throws CMSException on CMSSignedData creation problem
     * @throws IOException on other problems
     */
    public static List<X509CertificateHolder> loadCert(@NonNull File p7bFile) throws CMSException, IOException {
        CMSSignedData signature = new CMSSignedData(Files.newInputStream(p7bFile.toPath()));
        return new ArrayList<>(signature.getCertificates().getMatches(null));
    }

    /**
     * Load unencrypted private key stored in PEM format
     * @param reader reader with cert data
     * @return KeyPair
     * @throws IOException on problem with reading cert data
     */
    public static KeyPair loadPrivateKey(@NonNull Reader reader) throws IOException {
        try (PEMParser pemParser = new PEMParser(reader)) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
            return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
        }
    }

    /**
     * Load cert stored in PEM format
     * @param reader reader with cert data
     * @return CertificateHolder
     * @throws IOException on problem with reading cert data
     */
    public static X509CertificateHolder loadPemCert(@NonNull Reader reader) throws IOException {
        try (PEMParser pemParser = new PEMParser(reader)) {
            Object parsedObj = pemParser.readObject();
            if (parsedObj instanceof X509CertificateHolder) {
                return (X509CertificateHolder) parsedObj;
            } else {
                throw new RuntimeException("The parsed object was not an X509CertificateHolder.");
            }
        }
    }

    /**
     * Load Private Key from given PKCS8 encrypted file
     * @param file file to extract Private key
     * @param password key protection password
     * @return PrivateKey
     * @throws IOException on problem with reading private key file
     * @throws PKCSException on problem with decrypting Private Key
     */
    public static PrivateKey loadPrivateKey(@NonNull File file, char[] password) throws IOException, PKCSException {

        @Cleanup PEMParser pp = new PEMParser(new BufferedReader(new FileReader(file)));

        Object object = pp.readObject();

        PrivateKey privateKey;

        InputDecryptorProvider i = new JcePKCSPBEInputDecryptorProviderBuilder().build(password);

        if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
            PrivateKeyInfo key = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(i);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            privateKey = converter.getPrivateKey(key);
        } else {
            throw new RuntimeException("Problem z ładowaniem klucza, niewłaściwa klasa " + object.getClass());
        }

        return privateKey;
    }

    /**
     * Signs message with given private key
     *
     * @param messageBytes wiadomość do podpisania
     * @param privateKey private key
     * @return byte array wth signed message
     * @throws IOException when problem with private key occurs
     * @throws RuntimeException in other cases
     */
    public static byte[] signMessage(byte[] messageBytes, @NonNull PrivateKey privateKey) throws IOException {

        RSADigestSigner signer = new RSADigestSigner(new SHA512Digest());
        signer.init(true, PrivateKeyFactory.createKey(privateKey.getEncoded()));
        signer.update(messageBytes, 0, messageBytes.length);

        try {
            return signer.generateSignature();
        } catch (Exception ex) {
            throw new RuntimeException("Cannot generate RSA signature. " + ex.getMessage(), ex);
        }
    }

    /**
     * Sign given Public Key based on CSR (create certificate)
     *
     * @param request CSR
     * @param tobeSigned public key to be signed
     * @param caCert CA Cert
     * @param caKey CA private key
     * @param from cert valid date from
     * @param to cert valid date to
     * @return Signed certificate
     * @throws IOException when problem with private key occurs
     * @throws OperatorCreationException on problem with cert extensions copy
     * @throws CertificateException on problem with cert extraction
     */
    public static X509Certificate createCertificate(@NonNull PKCS10CertificationRequest request, @NonNull PublicKey tobeSigned,
                                                    @NonNull X509Certificate caCert, @NonNull PrivateKey caKey,
                                                    @NonNull Date from, @NonNull Date to)
            throws IOException, OperatorCreationException, CertificateException {
        return createCertificate(request.getSubject(), tobeSigned, extractExtensions(request), caCert, caKey, from, to);
    }

    /**
     * Sign given Public Key based on given subject and extensions (create certificate)
     *
     * @param subject RSA cert subject
     * @param tobeSigned public key to be signed
     * @param extensions cert extensions array
     * @param caCert CA Cert
     * @param caKey CA private key
     * @param from cert valid date from
     * @param to cert valid date to
     * @return Signed certificate
     * @throws IOException when problem with private key occurs
     * @throws OperatorCreationException on problem with cert extensions add
     * @throws CertificateException on problem with cert extraction
     */
    public static X509Certificate createCertificate(@NonNull String subject, @NonNull PublicKey tobeSigned,
                                                    @NonNull Extension[] extensions, @NonNull X509Certificate caCert,
                                                    @NonNull PrivateKey caKey, @NonNull Date from, @NonNull Date to)
            throws IOException, OperatorCreationException, CertificateException {
        return createCertificate(new X500Name(subject), tobeSigned, extensions, caCert, caKey, from, to);
    }

    /**
     * Sign given Public Key based on given subject and extensions (create certificate)
     *
     * @param subject RSA cert subject in X500Name format
     * @param tobeSigned public key to be signed
     * @param extensions cert extensions array
     * @param caCert CA Cert
     * @param caKey CA private key
     * @param from cert valid date from
     * @param to cert valid date to
     * @return Signed certificate
     * @throws IOException when problem with private key occurs
     * @throws OperatorCreationException on problem with cert extensions add
     * @throws CertificateException on problem with cert extraction
     */
    public static X509Certificate createCertificate(@NonNull X500Name subject, @NonNull PublicKey tobeSigned,
                                                    @NonNull Extension[] extensions, @NonNull X509Certificate caCert,
                                                    @NonNull PrivateKey caKey, @NonNull Date from, @NonNull Date to)
            throws IOException, OperatorCreationException, CertificateException {

        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(tobeSigned.getEncoded());
        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caKey.getEncoded());

        X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
                new X500Name(caCert.getIssuerX500Principal().getName()),
                new BigInteger(64, new SecureRandom()),
                from,
                to,
                subject,
                subPubKeyInfo
        );

        for(Extension extension : extensions) {
            certGenerator.addExtension(extension);
        }

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
        X509CertificateHolder certificateHolder = certGenerator.build(sigGen);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
    }

    /**
     * Extracts cert extensions form given CSR
     *
     * @param csr CSR
     * @return cert extensions array
     */
    public static Extension[] extractExtensions(@NonNull PKCS10CertificationRequest csr) {

        List<Extension> res = new ArrayList<>();

        for(Attribute attribute : csr.getAttributes()) {
            // TODO: należy sprawdzić czy jest odpowiedniego typu - PKCSObjectIdentifiers.pkcs_9_at_extensionRequest
            for(ASN1Encodable value : attribute.getAttributeValues()) {
                Extensions extensions = Extensions.getInstance(value);
                for(ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                    res.add(extensions.getExtension(oid));
                }
            }
        }
        return res.toArray(new Extension[0]);
    }
}
