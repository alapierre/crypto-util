package io.alapierre.crypto.dss.common;

import eu.europa.esig.dss.model.DSSException;
import lombok.val;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.security.auth.login.FailedLoginException;
import java.io.IOException;
/**
 * @author Adrian Lapierre {@literal al@alapierre.io}
 * Copyrights by original author 2023.01.22
 */
 class ExceptionExtractorTest {

    @Test
    void extract() {

        val ex = new DSSException("test", new IOException("test 2", new FailedLoginException("błędny pin")));

        val res = ExceptionExtractor.extract(ex, FailedLoginException.class);

        Assertions.assertTrue(res.isPresent());

        System.out.println(res);

    }
}
