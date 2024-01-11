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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SM2DHKeyAgreementTest {

    private static final byte[] localPrivateKeyBytes = new byte[] {
            48, 65, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 39, 48, 37, 2, 1, 1, 4, 32, -28, 27, -70, 59, -96, 11, -78, -97, -63, -65, -54, -18, 46, 45, -82, 2, -23, -5, 87, -18, -12, 16, -89, 65, -45, -69, 62, -31, 57, -102, -77, 44
    };

    private static final byte[] peerPublicKeyBytes = new byte[] {
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, -104, -7, -27, -52, 72, -109, -40, 36, -102, -3, 113, -48, 13, -20, -8, -59, -119, 78, -119, 29, -68, 95, 75, -31, -62, -99, 32, 66, 6, -49, 95, 35, 119, 126, 127, -17, 39, 115, 78, 48, -60, -80, 76, 125, -54, 125, 126, 16, 96, 60, -24, -114, -78, -126, -67, -62, 120, -30, -39, 44, 101, 2, -2, -104
    };

    private static final byte[] expectedPreMasterSecret = new byte[]{
            -4, -125, 12, -77, 0, -126, 65, -41, 94, -63, -73, 117, -118, 98, 100, -122, 98, 34, 74, -120, 73, -74, -17, -40, 93, -12, 99, 107, 28, 20, 86, 2
    };

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("bgmprovider.tls.enableRFC8998", "true");
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void test() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(peerPublicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(localPrivateKeyBytes));
        // local
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2DH");
        keyAgreement.init( privateKey);
        keyAgreement.doPhase(publicKey, true);
        SecretKey preMasterSecret = keyAgreement.generateSecret("TlsPremasterSecret");
        Assert.assertArrayEquals(expectedPreMasterSecret, preMasterSecret.getEncoded());
    }
}
