/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler.gm;

import org.junit.Test;
import org.openeuler.sun.security.provider.certpath.AlgorithmChecker;
import org.openeuler.sun.security.validator.Validator;
import sun.security.util.DisabledAlgorithmConstraints;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;

import static org.openeuler.gm.TestUtils.getPath;

public class AlgorithmCheckerTest extends BaseTest {
    private static final String PATH = getPath("server.truststore");
    private static final char[] PASSWORD = "12345678".toCharArray();

    @Test
    public void test() throws KeyStoreException, CertPathValidatorException {
        DisabledAlgorithmConstraints disabledAlgorithmConstraints = DisabledAlgorithmConstraints.certPathConstraints();
        AlgorithmChecker algorithmChecker = new AlgorithmChecker(disabledAlgorithmConstraints,
                Validator.VAR_TLS_SERVER);

        KeyStore trustStore = getTrustStore();
        Certificate certificate = trustStore.getCertificate("server-sm2-sig");
        algorithmChecker.check(certificate);
    }

    private static KeyStore getTrustStore() {
        KeyStore keyStore;
        try (FileInputStream fileInputStream = new FileInputStream(PATH)) {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fileInputStream, PASSWORD);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return keyStore;
    }
}
