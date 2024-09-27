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

package org.openeuler.sdf.provider;

import org.openeuler.provider.AbstractEntries;
import org.openeuler.sdf.commons.config.SDFConfig;

import java.security.Provider;
import java.util.HashMap;
import java.util.List;

public class SDFEntries extends AbstractEntries {
    private static final boolean enableNonSM = SDFConfig.getInstance().isEnableNonSM();
    protected SDFEntries(Provider provider) {
        super(provider);
    }

    @Override
    protected void putServices(Provider provider) {
        putSymmetric(provider);
        putAsymmetric(provider);
        putDigest(provider);
        putHmac(provider);
        putRandom(provider);
        putKeyExchange(provider);
    }

    private void putSymmetric(Provider provider) {
        putSM1(provider);
        putSM4(provider);
        putSM7(provider);
        if (enableNonSM) {
            putAES(provider);
        }
    }

    private void putAsymmetric(Provider provider) {
        putSM2(provider);
        if (enableNonSM) {
            putRSA(provider);
        }
    }

    private void putDigest(Provider provider) {
        add(provider, "MessageDigest", "SM3", "org.openeuler.sdf.jca.digest.SDFDigestBase$SM3",
                createAliasesWithOid("1.2.156.10197.1.401"));

        if (enableNonSM) {
            add(provider, "MessageDigest", "MD5", "org.openeuler.sdf.jca.digest.SDFDigestBase$MD5");
            add(provider, "MessageDigest", "SHA", "org.openeuler.sdf.jca.digest.SDFDigestBase$SHA1",
                    createAliasesWithOid("1.3.14.3.2.26", "SHA-1", "SHA1"));
            add(provider, "MessageDigest", "SHA-224", "org.openeuler.sdf.jca.digest.SDFDigestBase$SHA224",
                    createAliasesWithOid("2.16.840.1.101.3.4.2.4"));
            add(provider, "MessageDigest", "SHA-256", "org.openeuler.sdf.jca.digest.SDFDigestBase$SHA256",
                    createAliasesWithOid("2.16.840.1.101.3.4.2.1"));
            add(provider, "MessageDigest", "SHA-384", "org.openeuler.sdf.jca.digest.SDFDigestBase$SHA384",
                    createAliasesWithOid("2.16.840.1.101.3.4.2.2"));
            add(provider, "MessageDigest", "SHA-512", "org.openeuler.sdf.jca.digest.SDFDigestBase$SHA512",
                    createAliasesWithOid("2.16.840.1.101.3.4.2.3"));
        }
    }

    private void putHmac(Provider provider) {

        add(provider, "KeyGenerator", "HmacSM3", "org.openeuler.sdf.jca.mac.SDFHmacKeyGeneratorCore$HmacSM3");
        add(provider, "Mac", "HmacSM3", "org.openeuler.sdf.jca.mac.SDFHmacCore$HmacSM3");

        if (enableNonSM) {
            String macOidBase = "1.2.840.113549.2.";
            List<String> macSHA1Aliases = createAliasesWithOid(macOidBase + "7");
            List<String> macSHA224Aliases = createAliasesWithOid(macOidBase + "8");
            List<String> macSHA256Aliases = createAliasesWithOid(macOidBase + "9");
            List<String> macSHA384Aliases = createAliasesWithOid(macOidBase + "10");
            List<String> macSHA512Aliases = createAliasesWithOid(macOidBase + "11");
            add(provider, "KeyGenerator", "HmacMD5", "org.openeuler.sdf.jca.mac.SDFHmacKeyGeneratorCore$HmacMD5");
            add(provider, "KeyGenerator", "HmacSHA1", "org.openeuler.sdf.jca.mac.SDFHmacKeyGeneratorCore$HmacSHA1",
                    macSHA1Aliases);
            add(provider, "KeyGenerator", "HmacSHA224", "org.openeuler.sdf.jca.mac.SDFHmacKeyGeneratorCore$HmacSHA224",
                    macSHA224Aliases);
            add(provider, "KeyGenerator", "HmacSHA256", "org.openeuler.sdf.jca.mac.SDFHmacKeyGeneratorCore$HmacSHA256",
                    macSHA256Aliases);
            add(provider, "KeyGenerator", "HmacSHA384", "org.openeuler.sdf.jca.mac.SDFHmacKeyGeneratorCore$HmacSHA384",
                    macSHA384Aliases);
            add(provider, "KeyGenerator", "HmacSHA512", "org.openeuler.sdf.jca.mac.SDFHmacKeyGeneratorCore$HmacSHA512",
                    macSHA512Aliases);

            add(provider, "Mac", "HmacMD5", "org.openeuler.sdf.jca.mac.SDFHmacCore$HmacMD5");
            add(provider, "Mac", "HmacSHA1", "org.openeuler.sdf.jca.mac.SDFHmacCore$HmacSHA1",
                    macSHA1Aliases);
            add(provider, "Mac", "HmacSHA224", "org.openeuler.sdf.jca.mac.SDFHmacCore$HmacSHA224",
                    macSHA224Aliases);
            add(provider, "Mac", "HmacSHA256", "org.openeuler.sdf.jca.mac.SDFHmacCore$HmacSHA256",
                    macSHA256Aliases);
            add(provider, "Mac", "HmacSHA384", "org.openeuler.sdf.jca.mac.SDFHmacCore$HmacSHA384",
                    macSHA384Aliases);
            add(provider, "Mac", "HmacSHA512", "org.openeuler.sdf.jca.mac.SDFHmacCore$HmacSHA512",
                    macSHA512Aliases);
        }
    }

    private void putSM1(Provider provider) {
        add(provider, "KeyGenerator", "SM1",
                "org.openeuler.sdf.jca.symmetric.SDFSM1KeyGenerator");
        add(provider, "AlgorithmParameters", "SM1",
                "com.sun.crypto.provider.AESParameters");

        add(provider, "Cipher", "SM1/ECB/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFSM1Cipher$SM1_ECB_PKCS5Padding",
                createAliases("SM1"));
        add(provider, "Cipher", "SM1/ECB/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFSM1Cipher$SM1_ECB_NoPadding");

        add(provider, "Cipher", "SM1/CBC/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFSM1Cipher$SM1_CBC_PKCS5Padding");
        add(provider, "Cipher", "SM1/CBC/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFSM1Cipher$SM1_CBC_NoPadding");
    }

    private void putSM4(Provider provider) {
        add(provider, "KeyGenerator", "SM4",
                "org.openeuler.sdf.jca.symmetric.SDFSM4KeyGenerator");
        add(provider, "AlgorithmParameters", "SM4",
                "com.sun.crypto.provider.AESParameters");

        add(provider, "Cipher", "SM4/ECB/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFSM4Cipher$SM4_ECB_PKCS5Padding",
                createAliases("SM4"));
        add(provider, "Cipher", "SM4/ECB/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFSM4Cipher$SM4_ECB_NoPadding");

        add(provider, "Cipher", "SM4/CBC/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFSM4Cipher$SM4_CBC_PKCS5Padding");
        add(provider, "Cipher", "SM4/CBC/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFSM4Cipher$SM4_CBC_NoPadding");
    }


    private void putSM7(Provider provider) {
        add(provider, "KeyGenerator", "SM7",
                "org.openeuler.sdf.jca.symmetric.SDFSM7KeyGenerator");
        add(provider, "AlgorithmParameters", "SM7",
                "org.openeuler.sdf.jca.symmetric.SDFSM7Parameters");

        add(provider, "Cipher", "SM7/ECB/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFSM7Cipher$SM7_ECB_PKCS5Padding",
                createAliases("SM4"));
        add(provider, "Cipher", "SM7/ECB/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFSM7Cipher$SM7_ECB_NoPadding");

        add(provider, "Cipher", "SM7/CBC/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFSM7Cipher$SM7_CBC_PKCS5Padding");
        add(provider, "Cipher", "SM7/CBC/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFSM7Cipher$SM7_CBC_NoPadding");
    }

    private void putAES(Provider provider) {
        add(provider, "KeyGenerator", "AES",
                "org.openeuler.sdf.jca.symmetric.SDFAESKeyGenerator");

        add(provider, "Cipher", "AES/CBC/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES_CBC_PKCS5Padding");
        add(provider, "Cipher", "AES/CBC/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES_CBC_NoPadding");
        add(provider, "Cipher", "AES/ECB/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES_ECB_PKCS5Padding");
        add(provider, "Cipher", "AES/ECB/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES_ECB_NoPadding");

        add(provider, "Cipher", "AES_128/CBC/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES128_CBC_PKCS5Padding");
        add(provider, "Cipher", "AES_128/CBC/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES128_CBC_NoPadding");
        add(provider, "Cipher", "AES_128/ECB/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES128_ECB_PKCS5Padding");
        add(provider, "Cipher", "AES_128/ECB/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES128_ECB_NoPadding");

        add(provider, "Cipher", "AES_192/CBC/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES192_CBC_PKCS5Padding");
        add(provider, "Cipher", "AES_192/CBC/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES192_CBC_NoPadding");
        add(provider, "Cipher", "AES_192/ECB/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES192_ECB_PKCS5Padding");
        add(provider, "Cipher", "AES_192/ECB/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES192_ECB_NoPadding");

        add(provider, "Cipher", "AES_256/CBC/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES256_CBC_PKCS5Padding");
        add(provider, "Cipher", "AES_256/CBC/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES256_CBC_NoPadding");
        add(provider, "Cipher", "AES_256/ECB/PKCS5Padding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES256_ECB_PKCS5Padding");
        add(provider, "Cipher", "AES_256/ECB/NoPadding",
                "org.openeuler.sdf.jca.symmetric.SDFAESCipher$AES256_ECB_NoPadding");
    }

    private void putSM2(Provider provider) {
        add(provider, "KeyFactory", "EC",
                "org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECKeyFactory",
                createAliases("EllipticCurve"));
        add(provider, "AlgorithmParameters", "EC",
                "org.openeuler.sdf.jca.asymmetric.sun.security.util.SDFECParameters",
                createAliases("EllipticCurve", "1.2.840.10045.2.1"));
        add(provider, "KeyPairGenerator", "SM2",
                "org.openeuler.sdf.jca.asymmetric.SDFSM2KeyPairGenerator");
        add(provider, "KeyFactory", "SM2",
                "org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECKeyFactory");
        add(provider, "AlgorithmParameters", "SM2",
                "org.openeuler.sdf.jca.asymmetric.sun.security.util.SDFECParameters",
                createAliasesWithOid("1.2.156.10197.1.301"));
        add(provider, "Cipher", "SM2",
                "org.openeuler.sdf.jca.asymmetric.SDFSM2Cipher");
        add(provider, "Signature", "SM3withSM2",
                "org.openeuler.sdf.jca.signature.SDFSM2Signature$SDFSM3WithSM2",
                createAliasesWithOid("1.2.156.10197.1.501"));
        add(provider, "KeyAgreement", "SM2",
                "org.openeuler.sdf.jsse.SDFSM2KeyAgreement");
    }

    private void putRSA(Provider provider) {
        String rsaOid = "1.2.840.113549.1.1";
        List<String> rsaAliases = createAliasesWithOid(rsaOid);
        String sha1withRSAOid2 = "1.3.14.3.2.29";

        HashMap<String, String> attrs = new HashMap<>(3);
        attrs.put("SupportedKeyClasses",
                "java.security.interfaces.RSAPublicKey" +
                        "|java.security.interfaces.RSAPrivateKey");

        add(provider, "KeyPairGenerator", "RSA",
                "org.openeuler.sdf.jca.asymmetric.SDFRSAKeyPairGenerator$Legacy",
                rsaAliases);

        add(provider, "Signature", "MD2withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$MD2withRSA",
                createAliasesWithOid(rsaOid + ".2"), attrs);
        add(provider, "Signature", "MD5withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$MD5withRSA",
                createAliasesWithOid(rsaOid + ".4"), attrs);
        add(provider, "Signature", "SHA1withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$SHA1withRSA",
                createAliasesWithOid(rsaOid + ".5", sha1withRSAOid2), attrs);
        add(provider, "Signature", "SHA224withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$SHA224withRSA",
                createAliasesWithOid(rsaOid + ".14"), attrs);
        add(provider, "Signature", "SHA256withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$SHA256withRSA",
                createAliasesWithOid(rsaOid + ".11"), attrs);
        add(provider, "Signature", "SHA384withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$SHA384withRSA",
                createAliasesWithOid(rsaOid + ".12"), attrs);
        add(provider, "Signature", "SHA512withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$SHA512withRSA",
                createAliasesWithOid(rsaOid + ".13"), attrs);
        add(provider, "Signature", "SHA512/224withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$SHA512_224withRSA",
                createAliasesWithOid(rsaOid + ".15"), attrs);
        add(provider, "Signature", "SHA512/256withRSA",
                "org.openeuler.sdf.jca.signature.SDFRSASignature$SHA512_256withRSA",
                createAliasesWithOid(rsaOid + ".16"), attrs);

        attrs.clear();
        attrs.put("SupportedModes", "ECB");
        attrs.put("SupportedPaddings", "NOPADDING|PKCS1PADDING|OAEPPADDING"
                + "|OAEPWITHMD5ANDMGF1PADDING"
                + "|OAEPWITHSHA1ANDMGF1PADDING"
                + "|OAEPWITHSHA-1ANDMGF1PADDING"
                + "|OAEPWITHSHA-224ANDMGF1PADDING"
                + "|OAEPWITHSHA-256ANDMGF1PADDING"
                + "|OAEPWITHSHA-384ANDMGF1PADDING"
                + "|OAEPWITHSHA-512ANDMGF1PADDING"
                + "|OAEPWITHSHA-512/224ANDMGF1PADDING"
                + "|OAEPWITHSHA-512/256ANDMGF1PADDING");
        attrs.put("SupportedKeyClasses", "java.security.interfaces.RSAPublicKey" +
                "|java.security.interfaces.RSAPrivateKey");
        add(provider, "Cipher", "RSA", "org.openeuler.sdf.jca.asymmetric.SDFRSACipher",
                null, attrs);
    }

    private void putRandom(Provider provider) {
        add(provider, "SecureRandom", "SDF", "org.openeuler.sdf.jca.random.SDFRandom");
    }

    private void putKeyExchange(Provider provider) {
        add(provider, "KeyAgreement", "GmTlsEccPremasterSecret",
                "org.openeuler.sdf.jsse.SDFECCKeyAgreement");
        add(provider, "KeyGenerator", "GMTlsMasterSecret",
                "org.openeuler.sdf.jsse.SDFGMTlsMasterSecretGenerator");
        add(provider, "KeyGenerator", "GMTlsKeyMaterial",
                "org.openeuler.sdf.jsse.SDFGMTlsKeyMaterialGenerator");
        add(provider, "KeyGenerator", "GMTlsPrf",
                "org.openeuler.sdf.jsse.SDFGMTlsPrfGenerator");
    }
}
