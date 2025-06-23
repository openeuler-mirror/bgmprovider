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
import org.openeuler.adaptor.X509CertImplAdapter;
import sun.security.util.ConstraintsParameters;
import sun.security.util.DisabledAlgorithmConstraints;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509CertImpl;

import java.io.FileInputStream;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static org.openeuler.gm.TestUtils.getPath;

public class DisabledAlgorithmConstraintsHandlerTest extends BaseTest {
    private static final String PATH = getPath("server.truststore");
    private static final char[] PASSWORD = "12345678".toCharArray();


    @Test
    public void testPermits() throws KeyStoreException, CertificateException {
        KeyStore trustStore = getTrustStore();
        Certificate cert = trustStore.getCertificate("server-sm2-sig");
        X509CertImpl x509Cert = X509CertImpl.toImpl((X509Certificate) cert);
        X509CertImplAdapter adapter = new X509CertImplAdapter(x509Cert);
        AlgorithmId algorithmId = adapter.getSigAlg();
        AlgorithmParameters currSigAlgParams = algorithmId.getParameters();
        String currSigAlg = x509Cert.getSigAlgName();
        ConstraintsParameters cp = new TestConstraintsParameters(cert);
        DisabledAlgorithmConstraints disabledAlgorithmConstraints = DisabledAlgorithmConstraints.certPathConstraints();
        DisabledAlgorithmConstraintsHandler.permits(disabledAlgorithmConstraints, currSigAlg, currSigAlgParams, cp,
                true);
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

    private static class TestConstraintsParameters implements ConstraintsParameters {
        private Certificate certificate;

        TestConstraintsParameters(Certificate certificate) {
            this.certificate = certificate;
        }

        @Override
        public boolean anchorIsJdkCA() {
            return false;
        }

        @Override
        public Set<Key> getKeys() {
            PublicKey publicKey = certificate.getPublicKey();
            return new HashSet<>(Collections.singleton(publicKey));
        }

        @Override
        public Date getDate() {
            return null;
        }

        @Override
        public String getVariant() {
            return null;
        }

        @Override
        public String extendedExceptionMsg() {
            return null;
        }
    }
}
