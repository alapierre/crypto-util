package io.alapierre.crypto.dss;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import io.alapierre.crypto.misc.DllUtil;
import lombok.extern.slf4j.Slf4j;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.alapierre.crypto.misc.DllUtil.resolveDllAbsolutePathAndFileName;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2021.11.20
 */
@Slf4j
public class DssUtil {

    private DssUtil() {
    }

    public static void printCerts() throws InvalidNameException {

        DllUtil.DllInfo dllInfo = resolveDllAbsolutePathAndFileName("/opt/proCertumSmartSign", "cryptoCertum3PKCS");

        try (SignatureTokenConnection token = new Pkcs11SignatureToken(dllInfo.getFullPath(), new StdinPasswordInputCallback(), 1)) {
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            int i = 0;
            for (DSSPrivateKeyEntry entry : keys) {
                System.out.println("Cert no " + (++i));
                X509Certificate cert = entry.getCertificate().getCertificate();
                Principal subject = cert.getSubjectDN();
                System.out.println("name: " + subject.getName());

                LdapName ldapDN = new LdapName(subject.getName());

                Map<String, String> m = ldapDN.getRdns().stream().
                        collect(Collectors.
                                toMap(Rdn::getType, rdn -> String.valueOf(rdn.getValue())));

                String cn = m.get("CN");
                System.out.println(cn);
            }
        }
    }
}
