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

import java.io.*;
import java.security.Provider;
import java.util.Map;
import java.util.Properties;

public class BGMJCEProvider extends Provider {

    public BGMJCEProvider() {
        super("BGMJCEProvider", 1.8d, "BGMJCEProvider");

        putEntries(this);
    }

    private static Properties getProp() {
        Properties props = new Properties();
        String bgmproviderConf = System.getProperty("bgmprovider.conf");
        if (bgmproviderConf == null) {
            return props;
        }

        File propFile = new File(bgmproviderConf);
        if (propFile.exists()) {
            try (InputStream is = new BufferedInputStream(new FileInputStream(propFile))) {
                props.load(is);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return props;
    }

    static void putEntries(Map<Object, Object> map) {
        Properties props = getProp();
        if (!"false".equalsIgnoreCase(props.getProperty("jce.sm2"))) {
            putSM2(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jce.sm3"))) {
            putSM3(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jce.sm4"))) {
            putSM4(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jce.hmacSM3"))) {
            putHmacSM3(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jce.signatureSM2withSM2"))) {
            putSignatureSM3withSM2(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jce.keypairGenerator"))) {
            putKeyPairGenerator(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jce.algorithmParameters"))) {
            putAlgorithmParameters(map);
        }
    }

    private static void putSM4(Map<Object, Object> map) {
        map.put("Cipher.SM4", "org.bouncycastle.jcajce.provider.symmetric.SM4$ECB");
        map.put("AlgorithmParameters.SM4", "org.bouncycastle.jcajce.provider.symmetric.SM4$AlgParams");
        map.put("AlgorithmParameterGenerator.SM4", "org.bouncycastle.jcajce.provider.symmetric.SM4$AlgParams$AlgParamGen");
        map.put("KeyGenerator.SM4", "org.bouncycastle.jcajce.provider.symmetric.SM4$AlgParams$KeyGen");
    }

    private static void putSM3(Map<Object, Object> map) {
        map.put("MessageDigest.SM3", "org.bouncycastle.jcajce.provider.digest.SM3$Digest");
    }

    private static void putHmacSM3(Map<Object, Object> map) {
        map.put("Mac.HmacSM3", "org.bouncycastle.jcajce.provider.digest.SM3$HashMac");
        map.put("KeyGenerator.HmacSM3", "org.bouncycastle.jcajce.provider.digest.SM3$KeyGenerator");
    }

    private static void putSignatureSM3withSM2(Map<Object, Object> map) {
        map.put("Signature.SM3withSM2", "org.bouncycastle.jcajce.provider.asymmetric.ec.GMSignatureSpi$sm3WithSM2");
        map.put("Alg.Alias.Signature.1.2.156.10197.1.501", "SM3withSM2");
        map.put("Alg.Alias.Signature.OID.1.2.156.10197.1.501", "SM3withSM2");
    }

    private static void putSM2(Map<Object, Object> map) {
        map.put("Cipher.SM2", "org.openeuler.SM2Cipher");
        map.put("KeyPairGenerator.SM2", "org.openeuler.SM2KeyPairGenerator");
        map.put("KeyAgreement.SM2", "org.openeuler.SM2KeyAgreement");
        map.put("KeyFactory.EC", "org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi$EC");
        map.put("Alg.Alias.KeyFactory.SM2", "EC");
        map.put("Alg.Alias.KeyFactory.1.2.840.10045.2.1", "EC");
    }

    private static void putKeyPairGenerator(Map<Object, Object> map) {
        map.put("KeyPairGenerator.EC", "org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$EC");
    }

    private static void putAlgorithmParameters(Map<Object, Object> map) {
        map.put("AlgorithmParameters.EC", "org.bouncycastle.jcajce.provider.asymmetric.ec.AlgorithmParametersSpi");
    }
}
