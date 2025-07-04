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

package org.openeuler.sdf.jsse;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.BGMJCEProvider;
import org.openeuler.BGMJSSEProvider;
import org.openeuler.sdf.commons.spec.SDFSecretKeySpec;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.SDFSM2GenParameterSpec;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.spec.ECCPremasterSecretKeySpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.openeuler.sdf.jsse.util.SDFGMTLSKeyGenUtil.checkKeyMaterial;
import static org.openeuler.sdf.jsse.util.SDFGMTLSKeyGenUtil.generateECCPremasterSecretKeySpec;
import static org.openeuler.sdf.jsse.util.SDFGMTLSKeyGenUtil.generateKeyMaterial;
import static org.openeuler.sdf.jsse.util.SDFGMTLSKeyGenUtil.generateMasterSecret;

public class SDFECCKeyAgreementTest extends SDFTestCase {
    private static Provider sdfProvider;
    private static final Provider bmgJSSEProvider = new BGMJSSEProvider();
    private static final Provider bmgJCEProvider = new BGMJCEProvider();
    private static ECPublicKey publicKey;
    private static ECPrivateKey privateKey;

    @BeforeClass
    public static void beforeClass() throws Exception {
        System.setProperty("sdf.defaultKEKId", new String(SDFTestUtil.getTestKekId()));
        System.setProperty("sdf.defaultRegionId", new String(SDFTestUtil.getTestRegionId()));
        System.setProperty("sdf.defaultCdpId", new String(SDFTestUtil.getTestCdpId()));
        sdfProvider = new SDFProvider();
        Security.insertProviderAt(sdfProvider, 1);
        initParameters();
    }

    private static void initParameters() throws Exception {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("SM2");
        pairGenerator.initialize(new SDFSM2GenParameterSpec(
                SDFTestUtil.getTestKekId(),
                SDFTestUtil.getTestRegionId(),
                SDFTestUtil.getTestCdpId(),
                SDFTestUtil.getTestPin(),
                "sm2p256v1"));
        KeyPair serverKeyPair = pairGenerator.generateKeyPair();

        publicKey = (ECPublicKey) serverKeyPair.getPublic();
        privateKey = (ECPrivateKey) serverKeyPair.getPrivate();
    }

    @Test
    public void test() throws Exception {
        Cipher sm2Cipher = Cipher.getInstance("SM2");
        sm2Cipher.init(Cipher.DECRYPT_MODE, privateKey);
        ECCPremasterSecretKeySpec clientPremasterSecretSpec =
                generateECCPremasterSecretKeySpec(true, null,
                publicKey, privateKey, sdfProvider);
        sm2Cipher.update(clientPremasterSecretSpec.getEncryptedKey());
        byte[] clientPlainPreMasterKeyBytes = sm2Cipher.doFinal();

        ECCPremasterSecretKeySpec serverPremasterSecretSpec =
                generateECCPremasterSecretKeySpec(false, clientPremasterSecretSpec.getEncryptedKey(),
                        publicKey, privateKey, sdfProvider);
        sm2Cipher.update(serverPremasterSecretSpec.getEncryptedKey());
        byte[] serverPlainPreMasterKeyBytes = sm2Cipher.doFinal();

        Assert.assertEquals(clientPlainPreMasterKeyBytes.length, 48);
        Assert.assertArrayEquals(clientPlainPreMasterKeyBytes, serverPlainPreMasterKeyBytes);

        byte[] clientPreMasterKeyBytes = clientPremasterSecretSpec.getEncoded();
        byte[] serverPreMasterKeyBytes = serverPremasterSecretSpec.getEncoded();

        // enc key
        SecretKey clientPreMasterKey = new SDFSecretKeySpec(clientPreMasterKeyBytes,
                "GmTlsEccPremasterSecret", true);
        SecretKey serverPreMasterKey = new SDFSecretKeySpec(serverPreMasterKeyBytes,
                "GmTlsEccPremasterSecret", true);
        SecretKey clientMasterKey = generateMasterSecret(clientPreMasterKey, sdfProvider);
        SecretKey serverMasterKey = generateMasterSecret(serverPreMasterKey, sdfProvider);
        System.out.println("------------------------------------------------------------");
        TlsKeyMaterialSpec clientKeyMaterial = generateKeyMaterial(clientMasterKey, sdfProvider);
        System.out.println("------------------------------------------------------------");
        TlsKeyMaterialSpec serverKeyMaterial = generateKeyMaterial(serverMasterKey, sdfProvider);
        checkKeyMaterial(clientKeyMaterial, sdfProvider, serverKeyMaterial, sdfProvider);

        // plain key
        SecretKey clientPlainPreMasterKey = new SDFSecretKeySpec(clientPlainPreMasterKeyBytes,
                "GmTlsEccPremasterSecret", false);
        SecretKey serverPlainPreMasterKey = new SDFSecretKeySpec(serverPlainPreMasterKeyBytes,
                "GmTlsEccPremasterSecret", false);
        SecretKey clientPlainMasterKey = generateMasterSecret(clientPlainPreMasterKey, bmgJSSEProvider);
        SecretKey serverPlainMasterKey = generateMasterSecret(serverPlainPreMasterKey, bmgJSSEProvider);


        TlsKeyMaterialSpec clientPlainKeyMaterial = generateKeyMaterial(clientPlainMasterKey, bmgJSSEProvider);
        TlsKeyMaterialSpec serverPlainKeyMaterial = generateKeyMaterial(serverPlainMasterKey, bmgJSSEProvider);
        checkKeyMaterial(clientPlainKeyMaterial, bmgJCEProvider, serverPlainKeyMaterial, bmgJCEProvider);

        checkKeyMaterial(clientPlainKeyMaterial, bmgJCEProvider, clientKeyMaterial, sdfProvider);
        checkKeyMaterial(serverPlainKeyMaterial, bmgJCEProvider, serverKeyMaterial, sdfProvider);
    }

}
