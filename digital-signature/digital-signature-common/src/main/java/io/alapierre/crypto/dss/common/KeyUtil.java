package io.alapierre.crypto.dss.common;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.List;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.01.19
 */
@Slf4j
public class KeyUtil {

    public static DSSPrivateKeyEntry findValidKey(@NonNull List<DSSPrivateKeyEntry> keys) {

        Date now = new Date();

        for (DSSPrivateKeyEntry k : keys) {
            Date endDate = k.getCertificate().getNotAfter();
            Date startDate = k.getCertificate().getNotBefore();

            log.debug("sprawdzam certyfikat {} {}", startDate, endDate);

            if(isDayInRange(now, startDate, endDate)) return k;
        }

        throw new IllegalStateException("Brak ważnego certyfikatu");
    }

    public static boolean isDayInRange(@NonNull Date day, @NonNull Date from, @NonNull Date to) {
        return !(day.before(from) || day.after(to));
    }

}
