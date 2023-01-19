package io.alapierre.crypto.dss.common.misc;

import lombok.Value;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.file.Paths;

/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 *
 */
@Slf4j
public class DllUtil {

    /**
     * Dla podanej nazwy katalogu i nazwy biblioteki zwraca bezwzględną ścieżkę i nazwę pliku biblioteki (.dll lub .so)
     * w zależności od systemu operacyjnego
     *
     * @param relativePathToDll względna ścieżka do katalogu z bibliotekami
     * @param dllName nazwa biblioteki bez rozszerzenia
     * @return para ścieżka, nazwa pliku biblioteki
     */
    public static DllInfo resolveDllAbsolutePathAndFileName(String relativePathToDll, String dllName) {
        String pathToDll = Paths.get(relativePathToDll).toAbsolutePath().toString();
        String dllFileName = System.mapLibraryName(dllName);
        log.debug("absolute path to PKCS11 card library: {}", pathToDll + File.separator + dllFileName);
        return new DllInfo(pathToDll, dllFileName);
    }

    @Value
    public static class DllInfo {
        String pathToDll;
        String dllFileName;

        public String getFullPath() {
            return pathToDll + File.separator + dllFileName;
        }
    }

}


