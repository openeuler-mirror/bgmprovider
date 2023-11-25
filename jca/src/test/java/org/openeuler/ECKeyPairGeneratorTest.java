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

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

public class ECKeyPairGeneratorTest {

    private static final String[] GM_NAMED_CURVES = new String[]{
            "sm2p256v1", "1.2.156.10197.1.301",
            "wapip192v1", "1.2.156.10197.1.301.101",
    };

    private static final String[] N_GM_NAMED_CURVES = new String[]{
            "secp256r1", "1.2.840.10045.3.1.7",
            "secp384r1", "1.3.132.0.34",
            "secp521r1", "1.3.132.0.35",
    };

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new BGMJCEProvider(), 1);
    }

    @Test
    public void generateECKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        for (String nameCurve : GM_NAMED_CURVES) {
            System.out.println("test GM: " + nameCurve);
            generateKeyPair(new ECGenParameterSpec(nameCurve), "EC");
        }

        for (String nameCurve : N_GM_NAMED_CURVES) {
            System.out.println("test non-GM: " + nameCurve);
            generateKeyPair(new ECGenParameterSpec(nameCurve), "EC");
        }
    }

    @Test
    public void generateSM2KeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        for (String nameCurve : GM_NAMED_CURVES) {
            System.out.println("test GM: " + nameCurve);
            generateKeyPair(new ECGenParameterSpec(nameCurve), "SM2");
        }

        if (BGMJCEConfig.useLegacy()) {
            return;
        }

        boolean success = true;
        for (String nameCurve : N_GM_NAMED_CURVES) {
            System.out.println("test non-GM: " + nameCurve);
            try {
                generateKeyPair(new ECGenParameterSpec(nameCurve), "SM2");
                success = false;
            } catch (InvalidAlgorithmParameterException e) {
                // skip
            }
            Assert.assertTrue("Unable to generate non-GM ECPrivateKey", success);
        }
    }

    private void generateKeyPair(AlgorithmParameterSpec params, String algorithm)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(params);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Assert.assertTrue("Illegal EC private key type", keyPair.getPrivate() instanceof ECPrivateKey);
        Assert.assertTrue("Illegal EC public key type", keyPair.getPublic() instanceof ECPublicKey);
    }

    @Test
    public void getInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BGMJCEProvider");
        keyPairGenerator = KeyPairGenerator.getInstance("EC");
        Assert.assertEquals("Not expected KeyPairGenerator instance",
                keyPairGenerator.getProvider().getName(), "BGMJCEProvider");
    }

}
