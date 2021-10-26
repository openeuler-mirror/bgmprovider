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

package org.openeuler.gm;

import org.junit.Assert;
import org.junit.Test;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

@SuppressWarnings("deprecation")
public class GMTlsKeyMaterialGeneratorTest extends BaseTest {

    // master secret key
    private static final SecretKey MASTER_SECRET_KEY = new SecretKeySpec(new byte[]{
            -64, 67, 17, 117, -76, 30, 3, -113, -113, 123, 12, -19, 12, 124, 86, -109,
            89, 0, -70, 99, -24, -86, 58, 6, -50, 6, -44, 55, 122, -100, 53, 20,
            50, 62, -45, -127, 107, -32, 17, -107, 101, -96, -73, -102, -92, -37, -51, 95
    }, "TlsMasterSecret");

    // client random bytes
    private static final byte[] CLIENT_RANDOM_BYTES = new byte[]{
            34, -13, -128, 41, -88, 102, -99, 94, -97, 8, -7, 14, 48, -88, 14, 36,
            -81, 109, 124, 76, -43, -11, 114, 61, -100, 96, -74, 74, -13, -51, 39, 49
    };

    // server random bytes
    private static final byte[] SERVER_RANDOM_BYTES = new byte[]{
            8, -90, -57, -28, -109, 23, 75, -64, -29, -44, -99, -118, -69, -64, -28, 53,
            -83, -111, -9, -104, 69, -90, -4, -23, 61, 22, -96, 70, 113, 94, -123, 24
    };

    // expected client mac key
    private static final byte[] EXPECTED_CLIENT_MAC_KEY = new byte[]{
            39, -25, -62, 96, 68, -72, 27, 40, 37, 54, 58, -28, 124, 77, -67, -97,
            111, 1, -37, -102, -12, 100, 39, -25, -63, 3, 39, -110, -28, -95, 120, 70
    };

    // expected server mac key
    private static final byte[] EXPECTED_SERVER_MAC_KEY = new byte[]{
            -2, -85, 45, -8, 110, 99, -84, 45, -22, -59, -127, -31, -52, -87, -105, -31,
            43, 33, 18, 124, -17, -13, 46, -83, -127, 95, -51, -7, -33, 83, -74, -98
    };

    // expected client cipher key
    private static final byte[] EXPECTED_CLIENT_CIPHER_KEY = new byte[]{
            36, -105, 3, -94, 86, -8, 2, 4, 67, -48, -51, 3, -114, 85, 48, -66
    };

    // expected server cipher key
    private static final byte[] EXPECTED_SERVER_CIPHER_KEY = new byte[]{
            47, 8, -18, 18, 4, 0, 49, -97, 73, 60, -27, -69, 90, 65, 29, 41
    };

    // expected client iv
    private static final byte[] EXPECTED_CLIENT_IV = new byte[]{
            51, 7, -90, 49, 18, 82, 84, -116, -101, 122, 56, 51, 6, 55, -102, 107
    };

    // expected server iv
    private static final byte[] EXPECTED_SERVER_IV = new byte[]{
            97, -103, 100, 121, 6, 11, 22, -41, -116, 13, 71, 0, 112, 31, -18, -41
    };


    @Test
    public void testGenerateKey() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        TlsKeyMaterialParameterSpec parameterSpec = createParameterSpec();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsKeyMaterial");
        keyGenerator.init(parameterSpec);
        SecretKey secretKey = keyGenerator.generateKey();
        Assert.assertEquals(secretKey.getClass(), TlsKeyMaterialSpec.class);
        TlsKeyMaterialSpec tlsKeyMaterialSpec = (TlsKeyMaterialSpec) secretKey;

        // mac key
        SecretKey clientMacKey = tlsKeyMaterialSpec.getClientMacKey();
        SecretKey serverMacKey = tlsKeyMaterialSpec.getServerMacKey();
        Assert.assertArrayEquals(EXPECTED_CLIENT_MAC_KEY, clientMacKey.getEncoded());
        Assert.assertArrayEquals(EXPECTED_SERVER_MAC_KEY, serverMacKey.getEncoded());

        // cipher key
        SecretKey clientCipherKey = tlsKeyMaterialSpec.getClientCipherKey();
        SecretKey serverCipherKey = tlsKeyMaterialSpec.getServerCipherKey();
        Assert.assertArrayEquals(EXPECTED_CLIENT_CIPHER_KEY, clientCipherKey.getEncoded());
        Assert.assertArrayEquals(EXPECTED_SERVER_CIPHER_KEY, serverCipherKey.getEncoded());

        // iv
        IvParameterSpec clientIv = tlsKeyMaterialSpec.getClientIv();
        IvParameterSpec serverIv = tlsKeyMaterialSpec.getServerIv();
        Assert.assertArrayEquals(EXPECTED_CLIENT_IV, clientIv.getIV());
        Assert.assertArrayEquals(EXPECTED_SERVER_IV, serverIv.getIV());
    }

    private TlsKeyMaterialParameterSpec createParameterSpec() {
        return new TlsKeyMaterialParameterSpec(MASTER_SECRET_KEY,
                1, 1, CLIENT_RANDOM_BYTES, SERVER_RANDOM_BYTES,
                "SM4/CBC/NoPadding", 16, 0, 16,
                32, "SM3", 32, 64);
    }
}
