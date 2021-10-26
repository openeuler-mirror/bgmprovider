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

package org.openeuler;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.SM2KeyExchangeParameterSpec;
import org.openeuler.SM2KeyExchangeUtil;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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

    private static final byte[] peerPublicKeyBytes = new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, 127, 14, -101, -105, 81, -74, -41, 1, 79, -114, 78, 11, -21, -18, -68, 18, -14, -22, -101, -5, -101, 60, -38, 21, -120, -32, -109, -74, 48, -22, 113, 42, 122, -64, 108, 8, -110, 78, -50, -73, -17, -105, -44, 102, -28, -120, -125, 105, 73, 62, 101, 22, -57, -77, 109, -121, 58, -80, 51, 78, 82, -108, 93, 104
    };

    private static final byte[] peerPrivateKeyBytes = new byte[]{
            48, -127, -109, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 4, 121, 48, 119, 2, 1, 1, 4, 32, -4, 63, 65, -64, 68, 66, 15, -50, 22, 44, -14, 43, -87, -114, -87, -93, -73, 106, 78, 75, 29, 88, -89, 10, 32, -90, 47, 57, -111, -86, 25, -68, -96, 10, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, -95, 68, 3, 66, 0, 4, 127, 14, -101, -105, 81, -74, -41, 1, 79, -114, 78, 11, -21, -18, -68, 18, -14, -22, -101, -5, -101, 60, -38, 21, -120, -32, -109, -74, 48, -22, 113, 42, 122, -64, 108, 8, -110, 78, -50, -73, -17, -105, -44, 102, -28, -120, -125, 105, 73, 62, 101, 22, -57, -77, 109, -121, 58, -80, 51, 78, 82, -108, 93, 104
    };

    private static final byte[] EXPECTED_SHARED_KEY = new byte[]{
            94, -65, -33, -21, 117, -104, -103, 68, 93, -118, -110, 79, 4, 89, -78, -100, 95, -63, 13, 88, 94, 7, 31, 89, -27, 63, 15, 42, -66, 107, 45, -59, 9, -37, 105, 73, 32, -104, 18, 28, 9, -15, 37, -22, 2, -126, -100, 91
    };

    private static ECPublicKey localPublicKey;
    private static ECPrivateKey localPrivateKey;
    private static ECPublicKey peerPublicKey;
    private static ECPrivateKey peerPrivateKey;
    private static byte[] localId;
    private static BigInteger localRandom;
    private static ECPoint localR;
    private static byte[] peerId;
    private static BigInteger peerRandom;
    private static ECPoint peerR;
    private static final int secretLen = 48;

    @BeforeClass
    public static void beforeClass() throws Exception {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
        initParameters();
    }

    private static void initParameters() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        localPublicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(localPublicKeyBytes));
        localPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(localPrivateKeyBytes));
        localId = "1234567812345678".getBytes();
        localRandom = new BigInteger("77a7e3e5db41faceb224e2216524ebd532db4b222108f79de052e5b3dfc11b2a", 16);
        localR = SM2KeyExchangeUtil.generateR(localPublicKey, localRandom);

        peerPublicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(peerPublicKeyBytes));
        peerPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(peerPrivateKeyBytes));
        peerId = "1234567812345678".getBytes();
        peerRandom = new BigInteger("37cc2eb9aab471afcfd7bcda2d5b9e8665df5f45a781609c1dbac9b86e49ab1e", 16);
        peerR = SM2KeyExchangeUtil.generateR(peerPublicKey, peerRandom);
    }

    @Test
    public void testGenerateSecret() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(localPublicKey,
                localId, localRandom, peerR.getEncoded(false), peerId, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        Assert.assertArrayEquals(EXPECTED_SHARED_KEY, sharedSecret);

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(peerPublicKey,
                peerId, peerRandom, localR.getEncoded(false), localId, secretLen, false);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();
        Assert.assertArrayEquals(sharedSecret, peerSharedSecret);
    }

    @Test
    public void testNoneLocalPublic() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(
                localId, localRandom, peerR.getEncoded(false), peerId, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        Assert.assertArrayEquals(EXPECTED_SHARED_KEY, sharedSecret);

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(
                peerId, peerRandom, localR.getEncoded(false), localId, secretLen, false);
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
        KeyPair peerKeyPair = keyPairGenerator.generateKeyPair();

        ECPublicKey localPublicKey = (ECPublicKey) localKeyPair.getPublic();
        ECPrivateKey localPrivateKey = (ECPrivateKey) localKeyPair.getPrivate();
        ECPublicKey peerPublicKey = (ECPublicKey) peerKeyPair.getPublic();
        ECPrivateKey peerPrivateKey = (ECPrivateKey) peerKeyPair.getPrivate();
        BigInteger localRandom = SM2KeyExchangeUtil.generateRandom(localPublicKey, new SecureRandom());
        BigInteger peerRandom = SM2KeyExchangeUtil.generateRandom(peerPublicKey, new SecureRandom());
        ECPoint localR = SM2KeyExchangeUtil.generateR(localPublicKey, localRandom);
        ECPoint peerR = SM2KeyExchangeUtil.generateR(peerPublicKey, peerRandom);
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(localPublicKey,
                localId, localRandom, peerR.getEncoded(false), peerId, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        SM2KeyExchangeParameterSpec peerParameterSpec = new SM2KeyExchangeParameterSpec(peerPublicKey,
                peerId, peerRandom, localR.getEncoded(false), localId, secretLen, false);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerPrivateKey, peerParameterSpec, null);
        peerKeyAgreement.doPhase(localPublicKey, true);
        byte[] peerSharedSecret = peerKeyAgreement.generateSecret();
        Assert.assertArrayEquals(sharedSecret, peerSharedSecret);
    }

    @Test(expected = IllegalStateException.class)
    public void testNotInit() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(localPublicKey,
                localId, localRandom, peerR.getEncoded(false), peerId, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.doPhase(peerPublicKey, true);
        keyAgreement.generateSecret();
    }

    @Test(expected = IllegalStateException.class)
    public void testNotDoPhase() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(localPublicKey,
                localId, localRandom, peerR.getEncoded(false), peerId, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
        keyAgreement.generateSecret();
    }

    @Test
    public void testInit() throws Exception {
        SM2KeyExchangeParameterSpec parameterSpec = new SM2KeyExchangeParameterSpec(localPublicKey,
                localId, localRandom, peerR.getEncoded(false), peerId, secretLen, true);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(localPrivateKey, parameterSpec, null);
    }
}
