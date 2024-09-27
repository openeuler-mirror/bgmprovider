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
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.jsse.util.SDFSM2PreSecretUtil;
import org.openeuler.sun.security.internal.spec.TlsMasterSecretParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * GMTlsMasterSecretGenerator test
 */
@SuppressWarnings("deprecation")
public class SDFGMTlsMasterSecretGeneratorTest {

    private static final int ENC_MASTER_KEY_LEN = 512;


    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }



    /**
     * Test generate master key
     */
    @Test
    public void testGenerateMasterKey() throws Exception {
        // client
        SecretKey cMasterSecret = SDFSM2PreSecretUtil.getClientMasterSecret();
        Assert.assertEquals(ENC_MASTER_KEY_LEN, cMasterSecret.getEncoded().length);
        // server
        SecretKey sMasterSecret = SDFSM2PreSecretUtil.getServerMasterSecret();
        Assert.assertEquals(ENC_MASTER_KEY_LEN, sMasterSecret.getEncoded().length);

        // check master key
        Assert.assertArrayEquals(cMasterSecret.getEncoded(), sMasterSecret.getEncoded());
    }

    /**
     * Test not initialized before generating the key
     */
    @Test(expected = IllegalStateException.class)
    public void testNotInit() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator.generateKey();
    }

    /**
     * Test invalid AlgorithmParameterSpec
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testInvalidAlgorithmParameterSpec() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator.init(new AlgorithmParameterSpec() {
            @Override
            public int hashCode() {
                return super.hashCode();
            }
        });
    }

    /**
     * Test invalid GM TLS protocol version
     */
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testInvalidGMTLSProtocolVersion()
            throws Exception {
        TlsMasterSecretParameterSpec parameterSpec = SDFSM2PreSecretUtil.createMasterSecretParameterSpec(1, 0, true);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret");
        keyGenerator.init(parameterSpec);
    }
}
