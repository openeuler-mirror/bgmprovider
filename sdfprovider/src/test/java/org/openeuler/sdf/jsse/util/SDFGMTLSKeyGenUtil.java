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

package org.openeuler.sdf.jsse.util;

import org.junit.Assert;
import org.openeuler.spec.ECCPremasterSecretKeySpec;
import org.openeuler.sun.security.internal.spec.TlsECCKeyAgreementParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialSpec;
import org.openeuler.sun.security.internal.spec.TlsMasterSecretParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Arrays;

public class SDFGMTLSKeyGenUtil {
    private static final String MESSAGE = "1234567812345678";
    private static final int GMTLS_VERSION = 0x0101;
    private static final byte[] CLIENT_RANDOM_BYTES = new byte[]{
            34, -13, -128, 41, -88, 102, -99, 94, -97, 8, -7, 14, 48, -88, 14, 36,
            -81, 109, 124, 76, -43, -11, 114, 61, -100, 96, -74, 74, -13, -51, 39, 49
    };

    // server random bytes
    private static final byte[] SERVER_RANDOM_BYTES = new byte[]{
            34, -13, -128, 41, -88, 102, -99, 94, -97, 8, -7, 14, 48, -88, 14, 36,
            -81, 109, 124, 76, -43, -11, 114, 61, -100, 96, -74, 74, -13, -51, 39, 49
    };

    static  {
        Arrays.fill(CLIENT_RANDOM_BYTES, (byte) 1);
        Arrays.fill(SERVER_RANDOM_BYTES, (byte) 1);
    }

    private static void checkIv(TlsKeyMaterialSpec clientKeyMaterial,
                                TlsKeyMaterialSpec serverKeyMaterial) {
        Assert.assertArrayEquals(clientKeyMaterial.getClientIv().getIV(), serverKeyMaterial.getClientIv().getIV());
        Assert.assertArrayEquals(clientKeyMaterial.getServerIv().getIV(), serverKeyMaterial.getServerIv().getIV());
    }

    private static void checkMacKey(TlsKeyMaterialSpec clientKeyMaterial, Provider clientProvider,
                                    TlsKeyMaterialSpec serverKeyMaterial, Provider serverProvider) throws Exception {
        byte[] clientMac = mac(clientKeyMaterial.getClientMacKey(), clientProvider);
        byte[] serverMac = mac(serverKeyMaterial.getClientMacKey(), serverProvider);
        Assert.assertArrayEquals(clientMac, serverMac);

        clientMac = mac(clientKeyMaterial.getServerMacKey(), clientProvider);
        serverMac = mac(serverKeyMaterial.getServerMacKey(), serverProvider);
        Assert.assertArrayEquals(clientMac, serverMac);
    }

    private static byte[] mac(SecretKey macKey, Provider provider) throws Exception {
        Mac mac = Mac.getInstance("HmacSM3", provider);
        mac.init(macKey);
        return mac.doFinal(MESSAGE.getBytes());
    }

    private static void checkCipherKey(TlsKeyMaterialSpec clientKeyMaterial, Provider clientProvider,
                                       TlsKeyMaterialSpec serverKeyMaterial, Provider serverProvider) throws Exception {

        byte[] data = MESSAGE.getBytes();
        byte[] encData = encrypt(clientKeyMaterial.getClientCipherKey(), clientKeyMaterial.getClientIv(), data,
                clientProvider);
        byte[] decData = decrypt(serverKeyMaterial.getClientCipherKey(), serverKeyMaterial.getClientIv(), encData,
                serverProvider);
        Assert.assertArrayEquals(data, decData);

        encData = encrypt(clientKeyMaterial.getServerCipherKey(), clientKeyMaterial.getServerIv(), data,
                clientProvider);
        decData = decrypt(serverKeyMaterial.getServerCipherKey(), serverKeyMaterial.getServerIv(), encData,
                serverProvider);
        Assert.assertArrayEquals(data, decData);
    }

    private static byte[] encrypt(SecretKey cipherKey, IvParameterSpec ivParameterSpec, byte[] data,
                                  Provider provider) throws Exception {
        System.out.println(new String(cipherKey.getEncoded()));
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", provider);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivParameterSpec);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(SecretKey cipherKey, IvParameterSpec ivParameterSpec, byte[] encData,
                                  Provider provider) throws Exception {
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", provider);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivParameterSpec);
        return cipher.doFinal(encData);
    }

    public static void checkKeyMaterial(TlsKeyMaterialSpec clientKeyMaterial, Provider clientProvider,
                                        TlsKeyMaterialSpec serverKeyMaterial, Provider serverProvider) throws Exception {
        checkIv(clientKeyMaterial, serverKeyMaterial);
        checkCipherKey(clientKeyMaterial, clientProvider, serverKeyMaterial, serverProvider);
        checkMacKey(clientKeyMaterial, clientProvider, serverKeyMaterial, serverProvider);
    }

    // generate preMasterSecret
    @SuppressWarnings("deprecation")
    public static ECCPremasterSecretKeySpec generateECCPremasterSecretKeySpec(boolean isClient, byte[] pubEncCmk,
                                                                               PublicKey publicKey, PrivateKey privateKey,
                                                                               Provider provider)
            throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("GmTlsEccPremasterSecret", provider);
        TlsECCKeyAgreementParameterSpec parameterSpec;
        Key key;
        if (isClient) {
            parameterSpec = new TlsECCKeyAgreementParameterSpec(GMTLS_VERSION, GMTLS_VERSION);
            key = publicKey;
        } else {
            parameterSpec = new TlsECCKeyAgreementParameterSpec(pubEncCmk, GMTLS_VERSION, GMTLS_VERSION, false);
            key = privateKey;
        }
        keyAgreement.init(key, parameterSpec);
        return (ECCPremasterSecretKeySpec) keyAgreement.generateSecret("TlsEccPremasterSecret");
    }

    // generate master secret
    @SuppressWarnings("deprecation")
    public static SecretKey generateMasterSecret(SecretKey preMasterSecret, Provider provider) throws Exception {
        int majorVersion = (GMTLS_VERSION >>> 8) & 0xFF;
        int minorVersion = GMTLS_VERSION & 0xFF;
        TlsMasterSecretParameterSpec tlsMasterSecretParameterSpec = new TlsMasterSecretParameterSpec(
                preMasterSecret, majorVersion, minorVersion, CLIENT_RANDOM_BYTES,
                SERVER_RANDOM_BYTES,
                "SM3", 32, 64);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsMasterSecret", provider);
        keyGenerator.init(tlsMasterSecretParameterSpec);
        return keyGenerator.generateKey();
    }

    // generate key material (key expansion)
    @SuppressWarnings("deprecation")
    public static TlsKeyMaterialSpec generateKeyMaterial(SecretKey masterSecret, Provider provider) throws Exception {
        TlsKeyMaterialParameterSpec sTlsKeyMaterialParameterSpec = new TlsKeyMaterialParameterSpec(masterSecret,
                1, 1, CLIENT_RANDOM_BYTES, SERVER_RANDOM_BYTES,
                "SM4", 16, 0, 16,
                32, "SM3", 32, 64);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("GMTlsKeyMaterial", provider);
        keyGenerator.init(sTlsKeyMaterialParameterSpec);
        return (TlsKeyMaterialSpec) keyGenerator.generateKey();
    }

}
