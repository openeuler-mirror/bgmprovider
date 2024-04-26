/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import sun.security.util.ECUtil;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;

import java.security.spec.ECPoint;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * SM2KeyAgreement test
 */
public class SM2KeyAgreementTest {

    private static final byte[] localPublicKeyBytes = new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, 10, -36, -22, -20, 17, 26, 86, -114, -52, -78, 79, -22, 116, -47, -70, -33, 112, 32, -18, 92, -45, -58, 20, 36, -5, 55, 68, -95, -57, -121, 10, 33, -76, 54, 24, -119, -104, 61, -24, -113, 46, -57, 36, -78, -37, -95, -113, -52, -88, -5, 22, -67, 101, 94, 37, 2, -58, 55, -35, 15, -21, 31, -49, -80
    };
    private static final byte[] localPrivateKeyBytes = new byte[]{
            48, -127, -109, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 121, 48, 119, 2, 1, 1, 4, 32, -104, 71, 54, -41, 24, 66, 82, -45, 114, -113, -121, -105, -35, 35, 9, 49, -8, 119, 44, 118, 80, -20, 47, -38, -69, -47, 121, -8, -73, -33, 4, 54, -96, 10, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, -95, 68, 3, 66, 0, 4, 10, -36, -22, -20, 17, 26, 86, -114, -52, -78, 79, -22, 116, -47, -70, -33, 112, 32, -18, 92, -45, -58, 20, 36, -5, 55, 68, -95, -57, -121, 10, 33, -76, 54, 24, -119, -104, 61, -24, -113, 46, -57, 36, -78, -37, -95, -113, -52, -88, -5, 22, -67, 101, 94, 37, 2, -58, 55, -35, 15, -21, 31, -49, -80
    };
    private static final byte[] localTempPublicKeyBytes = new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, -85, 76, 39, -13, 114, -68, -44, -92, -54, 106, -76, -98, -1, -83, 90, 73, 108, 55, -110, 56, 41, 3, -111, -56, 18, 29, 13, 69, 118, 3, -98, 50, -10, -6, -43, -76, 27, 123, -125, 63, 125, -81, 8, 105, 83, 11, 126, 68, 62, -128, 72, -108, -107, 40, -98, -81, 108, -52, 93, -111, 31, -30, 125, 15
    };
    private static final byte[] localTempPrivateKeyBytes = new byte[] {
            48, 65, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 39, 48, 37, 2, 1, 1, 4, 32, 119, -89, -29, -27, -37, 65, -6, -50, -78, 36, -30, 33, 101, 36, -21, -43, 50, -37, 75, 34, 33, 8, -9, -99, -32, 82, -27, -77, -33, -63, 27, 42
    };

    private static final byte[] peerPublicKeyBytes = new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, 127, 14, -101, -105, 81, -74, -41, 1, 79, -114, 78, 11, -21, -18, -68, 18, -14, -22, -101, -5, -101, 60, -38, 21, -120, -32, -109, -74, 48, -22, 113, 42, 122, -64, 108, 8, -110, 78, -50, -73, -17, -105, -44, 102, -28, -120, -125, 105, 73, 62, 101, 22, -57, -77, 109, -121, 58, -80, 51, 78, 82, -108, 93, 104
    };

    private static final byte[] peerPrivateKeyBytes = new byte[]{
            48, -127, -109, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 121, 48, 119, 2, 1, 1, 4, 32, -4, 63, 65, -64, 68, 66, 15, -50, 22, 44, -14, 43, -87, -114, -87, -93, -73, 106, 78, 75, 29, 88, -89, 10, 32, -90, 47, 57, -111, -86, 25, -68, -96, 10, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, -95, 68, 3, 66, 0, 4, 127, 14, -101, -105, 81, -74, -41, 1, 79, -114, 78, 11, -21, -18, -68, 18, -14, -22, -101, -5, -101, 60, -38, 21, -120, -32, -109, -74, 48, -22, 113, 42, 122, -64, 108, 8, -110, 78, -50, -73, -17, -105, -44, 102, -28, -120, -125, 105, 73, 62, 101, 22, -57, -77, 109, -121, 58, -80, 51, 78, 82, -108, 93, 104
    };

    private static final byte[] peerTempPrivateKeyBytes = new byte[] {
            48, 65, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 39, 48, 37, 2, 1, 1, 4, 32, 55, -52, 46, -71, -86, -76, 113, -81, -49, -41, -68, -38, 45, 91, -98, -122, 101, -33, 95, 69, -89, -127, 96, -100, 29, -70, -55, -72, 110, 73, -85, 30
    };

    private static final byte[] peerTempPublicKeyBytes = new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, -120, -36, 119, -38, 57, 116, 126, -59, -68, -106, -27, -7, -43, 103, -48, 109, -117, 26, 84, 34, 23, -128, 86, 63, 19, 100, -62, -71, 103, -99, -108, 69, 14, -121, -62, 61, -30, 98, 36, -93, 106, 126, -109, 12, -112, 27, -57, -57, -104, 53, 21, -122, -119, 93, 95, -95, 102, 118, 99, -65, 62, 85, 30, 122
};

    private static final byte[] EXPECTED_SHARED_KEY = new byte[]{
            94, -65, -33, -21, 117, -104, -103, 68, 93, -118, -110, 79, 4, 89, -78, -100, 95, -63, 13, 88, 94, 7, 31, 89, -27, 63, 15, 42, -66, 107, 45, -59, 9, -37, 105, 73, 32, -104, 18, 28, 9, -15, 37, -22, 2, -126, -100, 91
    };

    private static byte[] localId;
    private static ECPublicKey localPublicKey;
    private static ECPrivateKey localPrivateKey;
    private static ECPublicKey localTempPublicKey;
    private static ECPrivateKey localTempPrivateKey;

    private static byte[] peerId;
    private static ECPublicKey peerPublicKey;
    private static ECPrivateKey peerPrivateKey;
    private static ECPublicKey peerTempPublicKey;
    private static ECPrivateKey peerTempPrivateKey;

    private static final int secretLen = 48;

    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        initParameters();
    }

    private static void initParameters() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        localId = "1234567812345678".getBytes();
        localPublicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(localPublicKeyBytes));
        localPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(localPrivateKeyBytes));
        localTempPublicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(localTempPublicKeyBytes));
        localTempPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(localTempPrivateKeyBytes));

        peerId = "1234567812345678".getBytes();
        peerPublicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(peerPublicKeyBytes));
        peerPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(peerPrivateKeyBytes));
        peerTempPublicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(peerTempPublicKeyBytes));
        peerTempPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(peerTempPrivateKeyBytes));

    }

    @Test
    public void testGenerateSecret() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        Assert.assertArrayEquals(EXPECTED_SHARED_KEY, sharedSecret);

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                peerId, peerPublicKey, peerTempPrivateKey, peerTempPublicKey,
                localId, localTempPublicKey, secretLen, false);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();
        Assert.assertArrayEquals(sharedSecret, peerSharedSecret);
    }

    @Test
    public void testNoneLocalPublic() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        Assert.assertArrayEquals(EXPECTED_SHARED_KEY, sharedSecret);

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                peerId, peerPublicKey, peerTempPrivateKey, peerTempPublicKey,
                localId, localTempPublicKey, secretLen, false);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();
        Assert.assertArrayEquals(sharedSecret, peerSharedSecret);
    }

    @Test
    public void testGenerateSecretRandomly() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");

        KeyPair localKeyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey localPublicKey = (ECPublicKey) localKeyPair.getPublic();
        ECPrivateKey localPrivateKey = (ECPrivateKey) localKeyPair.getPrivate();


        KeyPair localTempKeyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey localTempPublicKey = (ECPublicKey) localTempKeyPair.getPublic();
        ECPrivateKey localTempPrivateKey = (ECPrivateKey) localTempKeyPair.getPrivate();

        KeyPair peerKeyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
        ECPrivateKey peerPrivateKey = (ECPrivateKey) peerKeyPair.getPrivate();

        KeyPair peerTempKeyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey peerTempPublicKey = (ECPublicKey) peerTempKeyPair.getPublic();
        ECPrivateKey peerTempPrivateKey = (ECPrivateKey) peerTempKeyPair.getPrivate();

        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                peerId, peerPublicKey, peerTempPrivateKey, peerTempPublicKey,
                localId, localTempPublicKey, secretLen, false);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();
        Assert.assertArrayEquals(sharedSecret, peerSharedSecret);
    }

    @Test(expected = IllegalStateException.class)
    public void testNotInit() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.doPhase(peerPublicKey, true);
        keyAgreement.generateSecret();
    }

    @Test(expected = IllegalStateException.class)
    public void testNotDoPhase() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.generateSecret();
    }

    @Test
    public void testInit() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localPublicKey, localTempPrivateKey, localTempPublicKey,
                peerId, peerTempPublicKey, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
    }
}
