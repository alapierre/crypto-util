package io.alapierre.crypto.dss.common;

import eu.europa.esig.dss.model.DSSException;
import lombok.NonNull;

import java.util.Optional;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.01.22
 */
public class ExceptionExtractor {

    /**
     * Rekurencyjnie szuka wyjątku o podanym typie
     *
     * @param exception wyjątek, zawierający strukturę, w której należy szukać
     * @param wanted poszukiwany typ wyjątku
     * @return szukany obiekt wyjątku
     * @param <T> Typ szukanego wyjątku
     */
    public static <T> Optional<T> extract(@NonNull Throwable exception, @NonNull Class<T> wanted) {

        if (wanted.isInstance(exception)) {
            //noinspection unchecked
            return (Optional<T>) Optional.of(exception);
        }

        if(exception.getCause() != null) {
            return extract(exception.getCause(), wanted);
        } else return Optional.empty();
    }

}
