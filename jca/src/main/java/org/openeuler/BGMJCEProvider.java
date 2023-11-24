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

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

import java.io.*;
import java.lang.reflect.Field;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Properties;

import static org.openeuler.ObjectIdentifierHandler.newObjectIdentifier;

public class BGMJCEProvider extends Provider {
    private static final String OID_PKCS5_GM_PBES2 = "1.2.156.10197.6.1.4.1.5.2";

    static {
        initNameTable();
    }

    @SuppressWarnings("unchecked")
    private static void initNameTable() {
        try {
            Field nameTableFiled = AlgorithmId.class.getDeclaredField("nameTable");
            nameTableFiled.setAccessible(true);
            Object object = nameTableFiled.get(null);
            if (!(object instanceof Map)) {
                return;
            }
            Map<ObjectIdentifier,String> nameTable = (Map<ObjectIdentifier,String>) object;
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.104"), "SM4");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.301"), "SM2");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.401"), "SM3");
            nameTable.put(newObjectIdentifier("1.2.156.10197.1.501"), "SM3withSM2");
        } catch (NoSuchFieldException | IllegalAccessException | IOException e) {
            // skip
        }
    }

    private static class SecureRandomHolder {
        static final SecureRandom RANDOM = new SecureRandom();
    }

    public static SecureRandom getRandom() { return SecureRandomHolder.RANDOM; }


    public BGMJCEProvider() {
        super("BGMJCEProvider", 1.8d, "BGMJCEProvider");

        putEntries(this);
        CompatibleOracleJdkHandler.skipJarVerify(this);
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
        if (!"false".equalsIgnoreCase(props.getProperty("jce.algorithmParameters"))) {
            putAlgorithmParameters(map);
        }
        if (!"false".equalsIgnoreCase(props.getProperty("jce.pbes2"))) {
            putPBES2Algorithm(map);
        }
    }

    private static void putSM4(Map<Object, Object> map) {
        map.put("Cipher.SM4", "org.openeuler.sm4.SM4Cipher");
        map.put("AlgorithmParameters.SM4", "org.openeuler.sm4.SM4Parameters");
        map.put("AlgorithmParameterGenerator.SM4", "org.openeuler.sm4.SM4ParameterGenerator");
        map.put("KeyGenerator.SM4", "org.openeuler.sm4.SM4KeyGenerator");
    }

    private static void putSM3(Map<Object, Object> map) {
        map.put("MessageDigest.SM3", "org.openeuler.SM3");
        map.put("Alg.Alias.MessageDigest.OID.1.2.156.10197.1.401", "SM3");
        map.put("Alg.Alias.MessageDigest.1.2.156.10197.1.401", "SM3");
    }

    private static void putHmacSM3(Map<Object, Object> map) {
        map.put("Mac.HmacSM3", "org.openeuler.com.sun.crypto.provider.HmacCore$HmacSM3");
        map.put("KeyGenerator.HmacSM3", "org.openeuler.HmacSM3KeyGenerator");
    }

    private static void putSignatureSM3withSM2(Map<Object, Object> map) {
        map.put("Signature.SM3withSM2", "org.openeuler.SM2SignatureSpi$sm3WithSM2");
        map.put("Alg.Alias.Signature.1.2.156.10197.1.501", "SM3withSM2");
        map.put("Alg.Alias.Signature.OID.1.2.156.10197.1.501", "SM3withSM2");
    }

    private static void putSM2(Map<Object, Object> map) {
        map.put("Cipher.SM2", "org.openeuler.SM2Cipher");
        map.put("KeyPairGenerator.SM2", "org.openeuler.SM2KeyPairGenerator");
        map.put("KeyAgreement.SM2", "org.openeuler.SM2KeyAgreement");
        map.put("Alg.Alias.KeyFactory.SM2", "EC");
        map.put("Alg.Alias.KeyFactory.1.2.156.10197.1.301", "SM2");
        map.put("Alg.Alias.KeyFactory.OID.1.2.156.10197.1.301", "SM2");
        map.put("KeyFactory.EC", "org.openeuler.sun.security.ec.ECKeyFactory");
        map.put("Alg.Alias.KeyFactory.1.2.840.10045.2.1", "EC");
        map.put("Alg.Alias.KeyFactory.OID.1.2.840.10045.2.1", "EC");
        map.put("KeyPairGenerator.EC", "org.openeuler.ECCKeyPairGenerator");
    }

    private static void putAlgorithmParameters(Map<Object, Object> map) {
        map.put("AlgorithmParameters.EC", "org.openeuler.sun.security.util.ECParameters");
        map.put("Alg.Alias.AlgorithmParameters.1.2.840.10045.2.1", "EC");
        map.put("Alg.Alias.AlgorithmParameters.OID.1.2.840.10045.2.1", "EC");

        map.put("Alg.Alias.AlgorithmParameters.SM2", "EC");
        map.put("Alg.Alias.AlgorithmParameters.1.2.156.10197.1.301", "SM2");
        map.put("Alg.Alias.AlgorithmParameters.OID.1.2.156.10197.1.301", "SM2");
    }

    private static void putPBES2Algorithm(Map<Object, Object> map) {
        // AlgorithmParameters
        map.put("AlgorithmParameters.GMPBES2",
                "org.openeuler.com.sun.crypto.provider.PBES2Parameters$General");
        map.put("Alg.Alias.AlgorithmParameters.OID." + OID_PKCS5_GM_PBES2,
                "GMPBES2");
        map.put("Alg.Alias.AlgorithmParameters." + OID_PKCS5_GM_PBES2,
                "GMPBES2");
        map.put("AlgorithmParameters.PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Parameters$HmacSM3AndSM4_128_ECB_PKCS5Padding");
        map.put("AlgorithmParameters.PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Parameters$HmacSM3AndSM4_128_CBC_PKCS5Padding");
        map.put("Alg.Alias.AlgorithmParameters.PBEWithHmacSM3AndSM4_CBC", "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding");

        // Cipher
        map.put("Cipher.PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Core$HmacSM3AndSM4_128_ECB_PKCS5Padding");
        map.put("Cipher.PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Core$HmacSM3AndSM4_128_CBC_PKCS5Padding");
        map.put("Alg.Alias.Cipher.PBEWithHmacSM3AndSM4_CBC", "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding");

        // SecretKeyFactory
        map.put("SecretKeyFactory.PBKDF2WithHmacSM3",
                "org.openeuler.com.sun.crypto.provider.PBKDF2Core$HmacSM3");
        map.put("SecretKeyFactory.PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBEKeyFactory$PBEWithHmacSM3AndSM4_128_ECB_PKCS5Padding");
        map.put("SecretKeyFactory.PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBEKeyFactory$PBEWithHmacSM3AndSM4_128_CBC_PKCS5Padding");
        map.put("Alg.Alias.SecretKeyFactory.PBEWithHmacSM3AndSM4_CBC", "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding");

        // Mac
        map.put("Mac.HmacPBESM3",
                "org.openeuler.com.sun.crypto.provider.HmacPKCS12PBECore$HmacPKCS12PBESM3");
    }
}
