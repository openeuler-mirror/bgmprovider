/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.tomcat;

import static org.openeuler.tomcat.TestUtils.isEmpty;

public class TestParameters {

    public static final String DEFAULT_SSL_PROTOCOL = "TLS";
    private String sslProtocol;
    private String[] protocols;
    private String[] ciphers;
    private Cert[] certs;
    private String expectedCipher;

    private TestParameters() {

    }

    public String getSslProtocol() {
        return sslProtocol;
    }

    public String[] getProtocols() {
        return protocols;
    }

    public String[] getCiphers() {
        return ciphers;
    }

    public Cert[] getCerts() {
        return certs;
    }

    public String getExpectedCipher() {
        return expectedCipher;
    }

    static class Builder {
        private final String sslProtocol;
        private String[] protocols;
        private String[] ciphers;
        private Cert[] certs;
        private String expectedCipher;

        Builder() {
            this.sslProtocol = DEFAULT_SSL_PROTOCOL;
        }

        Builder(String sslProtocol) {
            this.sslProtocol = sslProtocol;
            if (isEmpty(sslProtocol)) {
                throw new IllegalArgumentException("The sslProtocol cannot be null");
            }
        }

        Builder protocols(String[] protocols) {
            this.protocols = protocols;
            return this;
        }

        Builder ciphers(String[] ciphers) {
            this.ciphers = ciphers;
            return this;
        }

        Builder certs(Cert[] certs) {
            this.certs = certs;
            return this;
        }

        Builder expectedCipher(String expectedCipher) {
            this.expectedCipher = expectedCipher;
            return this;
        }

        TestParameters builder() {
            TestParameters testParameters = new TestParameters();
            testParameters.sslProtocol = this.sslProtocol;
            testParameters.protocols = this.protocols;
            testParameters.ciphers = this.ciphers;
            testParameters.certs = this.certs;
            testParameters.expectedCipher = this.expectedCipher;
            return testParameters;
        }
    }
}
