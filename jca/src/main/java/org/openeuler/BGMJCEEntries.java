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

import org.openeuler.provider.AbstractEntries;

import java.security.Provider;

public class BGMJCEEntries extends AbstractEntries {
    protected BGMJCEEntries(Provider provider) {
        super(provider);
    }

    @Override
    protected void putServices(Provider provider) {
        // SM2
        if (BGMJCEConfig.enableSM2()) {
            putSM2(provider);
        }

        // EC
        if (BGMJCEConfig.enableEC()) {
            putEC(provider);
        }

        // SM3
        if (BGMJCEConfig.enableSM3()) {
            putSM3(provider);
        }

        // SM3withSM2
        if (BGMJCEConfig.enableSM3withSM2()) {
            putSM3withSM2(provider);
        }

        // SM4
        if (BGMJCEConfig.enableSM4()) {
            putSM4(provider);
        }

        // PBES2
        if (BGMJCEConfig.enablePBES2()) {
            putPBES2(provider);
        }
    }

    private void putSM2(Provider provider) {
        add(provider, "Cipher", "SM2",
                "org.openeuler.SM2Cipher");
        add(provider, "KeyPairGenerator", "SM2",
                "org.openeuler.SM2KeyPairGenerator");
        add(provider, "KeyAgreement", "SM2",
                "org.openeuler.SM2KeyAgreement");
        add(provider, "KeyFactory", "SM2",
                "org.openeuler.sun.security.ec.ECKeyFactory",
                createAliasesWithOid("1.2.156.10197.1.301"));
        add(provider, "AlgorithmParameters", "SM2",
                "org.openeuler.sun.security.util.ECParameters",
                createAliasesWithOid("1.2.156.10197.1.301"));

        if (BGMJCEConfig.enableRFC8998()) {
            add(provider, "KeyAgreement", "SM2DH",
                    "org.openeuler.SM2DHKeyAgreement");
            add(provider, "KeyAgreement", "ECDH",
                    "org.openeuler.ECDHKeyAgreementAdaptor");
        }
    }

    private void putEC(Provider provider) {
        add(provider, "KeyPairGenerator", "EC",
                "org.openeuler.ECCKeyPairGenerator");
        add(provider, "KeyFactory", "EC",
                "org.openeuler.sun.security.ec.ECKeyFactory",
                createAliasesWithOid("1.2.840.10045.2.1"));
        add(provider, "AlgorithmParameters", "EC",
                "org.openeuler.sun.security.util.ECParameters",
                createAliasesWithOid("1.2.840.10045.2.1"));
    }

    private void putSM3(Provider provider) {
        add(provider, "MessageDigest", "SM3",
                "org.openeuler.SM3",
                createAliasesWithOid("1.2.156.10197.1.401"));
        add(provider, "Mac", "HmacSM3",
                "org.openeuler.com.sun.crypto.provider.HmacCore$HmacSM3");
        add(provider, "KeyGenerator", "HmacSM3",
                "org.openeuler.HmacSM3KeyGenerator");
    }

    private void putSM3withSM2(Provider provider) {
        add(provider, "Signature", "SM3withSM2",
                "org.openeuler.SM2Signature$SM3withSM2",
                createAliasesWithOid("1.2.156.10197.1.501"));
    }

    private void putSM4(Provider provider) {
        add(provider, "Cipher", "SM4",
                "org.openeuler.com.sun.crypto.provider.SM4Cipher$General");
        add(provider, "AlgorithmParameters", "SM4",
                "org.openeuler.sm4.SM4Parameters");
        add(provider, "AlgorithmParameterGenerator", "SM4",
                "org.openeuler.sm4.SM4ParameterGenerator");
        add(provider, "KeyGenerator", "SM4",
                "org.openeuler.sm4.SM4KeyGenerator");
        add(provider, "AlgorithmParameters", "CCM",
                "org.openeuler.com.sun.crypto.provider.CCMParameters");
        add(provider, "AlgorithmParameters", "OCB",
                "org.openeuler.com.sun.crypto.provider.OCBParameters");
    }

    private void putPBES2(Provider provider) {
        add(provider, "AlgorithmParameters", "GMPBES2",
                "org.openeuler.com.sun.crypto.provider.PBES2Parameters$General",
                createAliasesWithOid("1.2.156.10197.6.1.4.1.5.2"));
        add(provider, "AlgorithmParameters", "PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Parameters$HmacSM3AndSM4_128_ECB_PKCS5Padding");
        add(provider, "AlgorithmParameters", "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Parameters$HmacSM3AndSM4_128_CBC_PKCS5Padding",
                createAliases("PBEWithHmacSM3AndSM4_CBC"));
        add(provider, "Cipher", "PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Core$HmacSM3AndSM4_128_ECB_PKCS5Padding");
        add(provider, "Cipher", "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBES2Core$HmacSM3AndSM4_128_CBC_PKCS5Padding",
                createAliases("PBEWithHmacSM3AndSM4_CBC"));
        add(provider, "SecretKeyFactory", "PBKDF2WithHmacSM3",
                "org.openeuler.com.sun.crypto.provider.PBKDF2Core$HmacSM3");
        add(provider, "SecretKeyFactory", "PBEWithHmacSM3AndSM4_128/ECB/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBEKeyFactory$PBEWithHmacSM3AndSM4_128_ECB_PKCS5Padding");
        add(provider, "SecretKeyFactory", "PBEWithHmacSM3AndSM4_128/CBC/PKCS5Padding",
                "org.openeuler.com.sun.crypto.provider.PBEKeyFactory$PBEWithHmacSM3AndSM4_128_CBC_PKCS5Padding",
                createAliases("PBEWithHmacSM3AndSM4_CBC"));
        add(provider, "Mac", "HmacPBESM3",
                "org.openeuler.com.sun.crypto.provider.HmacPKCS12PBECore$HmacPKCS12PBESM3");
    }
}
