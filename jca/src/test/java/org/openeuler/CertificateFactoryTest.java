/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class CertificateFactoryTest {

    /**
     * openssl ecparam -genkey -name SM2 -out sm2_private_key.pem -outform PEM
     * openssl req -new -key sm2_private_key.pem -out sm2.csr -subj "/CN=test" -sm3
     * openssl req -x509 -days 365 -key sm2_private_key.pem  -in sm2.csr -out sm2_cert.pem -sm3
     */
    private final static String SM2_CERT_BABASSL =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIBczCCARmgAwIBAgIUYDpHj+jEg2nAUSEYckUw7UPGvx0wCgYIKoEcz1UBg3Uw\n" +
                    "DzENMAsGA1UEAwwEdGVzdDAeFw0yMzEwMjQxMTEzNTlaFw0yNDEwMjMxMTEzNTla\n" +
                    "MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATaA/Bd\n" +
                    "ElIaWJ53Lga6XXEJtorz6jKKBnAgXj3Puc4HmRB/3ILnXb8tHp5kHb4mbHPDLHeU\n" +
                    "IL8WKnKCiY4pZg1to1MwUTAdBgNVHQ4EFgQUPFJLDyq+9soO9omIBJ8q5QAr2wAw\n" +
                    "HwYDVR0jBBgwFoAUPFJLDyq+9soO9omIBJ8q5QAr2wAwDwYDVR0TAQH/BAUwAwEB\n" +
                    "/zAKBggqgRzPVQGDdQNIADBFAiBCE5xpe4He1M2cCm/W4JFfvxsx5aXHevlkvYYX\n" +
                    "ouH+QAIhANz0oYcQ86/IJCJgZgYX34YILly8yIZycackwn6S0MTV\n" +
                    "-----END CERTIFICATE-----\n";

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void test() throws Exception {
        Certificate certificate = generateCertificate(SM2_CERT_BABASSL);
        System.out.println(certificate);
        certificate.verify(certificate.getPublicKey());
    }

    private Certificate generateCertificate(String certStr) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certStr.getBytes());
        return certificateFactory.generateCertificate(inputStream);
    }
}
