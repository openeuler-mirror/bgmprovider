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

package org.openeuler.sdf.jca.signature;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.asymmetric.SDFRSATestUtil;
import org.openeuler.sdf.provider.SDFProvider;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class SDFRSASignatureTest {
    private static final int[] KEY_SIZES = {1024, 2048, 3072, 4096};
    private static final String[] SIGNATURE_ALGORITHMS = {
            "MD2withRSA",
            "MD5withRSA",
            "SHA1withRSA",
            "SHA224withRSA",
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SHA512/224withRSA",
            "SHA512/256withRSA",
    };

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }


    @Test
    public void test() throws Exception {
        if (!SDFTestUtil.isEnableNonSM()) {
            System.out.println("skip test case testEncryptAndDecrypt");
            return;
        }
        for (int keySize : KEY_SIZES) {
            KeyPair keyPair = SDFRSATestUtil.generateKeyPair(keySize, "SDFProvider");
            for (String algorithm : SIGNATURE_ALGORITHMS) {
                System.out.println("Test algorithm=" + algorithm + ",keySize=" + keySize);
                test(algorithm, keyPair.getPrivate(), keyPair.getPublic());
            }
        }
    }

    private static void test(String algorithm, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        byte[] data = SDFTestUtil.generateRandomBytesByBound(256);
        byte[] jdkSignData = SDFRSATestUtil.sign(algorithm, "SunRsaSign", privateKey, data);
        byte[] sdfSignData = SDFRSATestUtil.sign(algorithm, "SDFProvider", privateKey, data);
        Assert.assertArrayEquals(jdkSignData, sdfSignData);

        boolean jdkVerify = SDFRSATestUtil.verify(algorithm, null, publicKey, data, sdfSignData);
        Assert.assertTrue(jdkVerify);

        boolean sdfVerify = SDFRSATestUtil.verify(algorithm, null, publicKey, data, sdfSignData);
        Assert.assertTrue(sdfVerify);
    }
}
