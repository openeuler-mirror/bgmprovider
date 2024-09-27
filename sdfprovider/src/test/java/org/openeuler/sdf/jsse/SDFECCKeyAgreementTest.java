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
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.SDFSM2GenParameterSpec;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.spec.ECCPremasterSecretKeySpec;
import org.openeuler.sun.security.internal.spec.TlsECCKeyAgreementParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class SDFECCKeyAgreementTest {

    private static int GMTLSProtocolVersion = 0x0101;
    private static ECPublicKey publicKey;
    private static ECPrivateKey privateKey;


    @BeforeClass
    public static void beforeClass() throws Exception {
        System.setProperty("sdf.defaultKEKId", new String(SDFTestUtil.getTestKekId()));
        System.setProperty("sdf.defaultRegionId", new String(SDFTestUtil.getTestRegionId()));
        System.setProperty("sdf.defaultCpdId", new String(SDFTestUtil.getTestCdpId()));
        Security.insertProviderAt(new SDFProvider(), 1);
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
        beforeClass();
        Cipher sm2Cipher = Cipher.getInstance("SM2");
        sm2Cipher.init(Cipher.DECRYPT_MODE, privateKey);
        ECCPremasterSecretKeySpec encryptSecret = (ECCPremasterSecretKeySpec) generateSecret();
        sm2Cipher.update(encryptSecret.getEncryptedKey());
        byte[] clientPreMasterKey = sm2Cipher.doFinal();

        ECCPremasterSecretKeySpec decryptSecret = (ECCPremasterSecretKeySpec) decode(encryptSecret.getEncryptedKey());
        sm2Cipher.update(decryptSecret.getEncryptedKey());
        byte[] serverPreMasterKey = sm2Cipher.doFinal();
        Assert.assertArrayEquals(clientPreMasterKey, serverPreMasterKey);
    }

    public static SecretKeySpec generateSecret() throws Exception {
        String algorithm = "GmTlsEccPremasterSecret";
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);

        TlsECCKeyAgreementParameterSpec spec =
                new TlsECCKeyAgreementParameterSpec(
                        GMTLSProtocolVersion,
                        GMTLSProtocolVersion);
        keyAgreement.init(publicKey, spec);
        return (ECCPremasterSecretKeySpec) keyAgreement.generateSecret("TlsEccPremasterSecret");
    }

    @SuppressWarnings("deprecation")
    static SecretKeySpec decode(byte[] encrypted) throws GeneralSecurityException {
        String algorithm = "GmTlsEccPremasterSecret";
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);
        TlsECCKeyAgreementParameterSpec spec =
                new TlsECCKeyAgreementParameterSpec(
                        encrypted,
                        GMTLSProtocolVersion,
                        GMTLSProtocolVersion,
                        false);
        keyAgreement.init(privateKey, spec);
        return (ECCPremasterSecretKeySpec) keyAgreement.generateSecret("TlsEccPremasterSecret");
    }


}
