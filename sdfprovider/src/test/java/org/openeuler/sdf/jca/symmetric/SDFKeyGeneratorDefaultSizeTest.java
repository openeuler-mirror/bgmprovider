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

package org.openeuler.sdf.jca.symmetric;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.commons.util.SDFTestUtil;
import org.openeuler.sdf.jca.symmetric.SDFSymmetricParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SDFKeyGeneratorDefaultSizeTest extends SDFTestCase {
    private static final byte[] PLAIN_BYTES = "hellohelloworld!".getBytes();

    private static  Provider sdfProvider = new SDFProvider();

    @Test
    public void testEncKeyDefault() throws Exception {
        testEncKeyDefault("SM4", "SM4/ECB/NOPADDING");
    }


    public void testEncKeyDefault(String keyalgo, String algo) throws Exception {
        // test enc key encrypt and decrypt
        testKeyGeneratorDefault(keyalgo, algo, sdfProvider);
    }

    private void testKeyGeneratorDefault(String keyalgo,String algo, Provider provider) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(keyalgo, provider);
        AlgorithmParameterSpec spec = new SDFSymmetricParameterSpec(SDFTestUtil.getTestKekId(),
                SDFTestUtil.getTestRegionId(), SDFTestUtil.getTestCdpId(), SDFTestUtil.getTestPin());
        keyGenerator.init(spec);
        SecretKey encKey = keyGenerator.generateKey();
        testCipher(encKey, algo, provider);
    }

    private void testCipher(SecretKey key, String algo, Provider provider) throws Exception {
        Cipher cipher = Cipher.getInstance(algo, provider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encBytes = cipher.doFinal(PLAIN_BYTES);

        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decBytes = cipher.doFinal(encBytes);
        if (!Arrays.equals(PLAIN_BYTES, decBytes)) {
            throw new RuntimeException(algo + " Failed. The SecretKey is " + key.getClass().getName());
        }
    }
}
