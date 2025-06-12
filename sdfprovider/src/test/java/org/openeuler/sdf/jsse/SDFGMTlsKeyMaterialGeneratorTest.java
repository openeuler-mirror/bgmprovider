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
import org.openeuler.sdf.commons.util.SDFTestCase;
import org.openeuler.sdf.provider.SDFProvider;
import org.openeuler.sdf.jsse.util.SDFSM2PreSecretUtil;
import org.openeuler.sun.security.internal.spec.TlsKeyMaterialSpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;

@SuppressWarnings("deprecation")
public class SDFGMTlsKeyMaterialGeneratorTest extends SDFTestCase {

    private static final int ENC_MAC_KEY_LEN = 1024;
    private static final int ENC_CIPHER_KEY_LEN = 1024;
    private static final int IV_LEN = 16;
    private static final String MESSAGE = "KeyMaterialGenerator test";

    @BeforeClass
    public static void beforeClass() {
        Security.insertProviderAt(new SDFProvider(), 1);
    }

    @Test
    public void testGenerateKey() throws Exception {
        // client mode
        SecretKey secretKey = SDFSM2PreSecretUtil.getClientBlockKey();
        Assert.assertEquals(secretKey.getClass(), TlsKeyMaterialSpec.class);
        TlsKeyMaterialSpec tlsKeyMaterialSpec = (TlsKeyMaterialSpec) secretKey;

        // server mode
        TlsKeyMaterialSpec tlsKeyMaterialSpec1 = (TlsKeyMaterialSpec) SDFSM2PreSecretUtil.getServerBlockKey();

        // mac key client mode
        SecretKey clientMacKey = tlsKeyMaterialSpec.getClientMacKey();
        SecretKey serverMacKey = tlsKeyMaterialSpec.getServerMacKey();
        Assert.assertEquals(ENC_MAC_KEY_LEN, clientMacKey.getEncoded().length);
        Assert.assertEquals(ENC_MAC_KEY_LEN, serverMacKey.getEncoded().length);
        // mac key server mode
        SecretKey clientMacKey1 = tlsKeyMaterialSpec1.getClientMacKey();
        SecretKey serverMacKey1 = tlsKeyMaterialSpec1.getServerMacKey();
        Assert.assertEquals(ENC_MAC_KEY_LEN, clientMacKey1.getEncoded().length);
        Assert.assertEquals(ENC_MAC_KEY_LEN, serverMacKey1.getEncoded().length);
        checkMacKey(clientMacKey, clientMacKey1);
        checkMacKey(serverMacKey, serverMacKey1);

        // cipher key client mode
        SecretKey clientCipherKey = tlsKeyMaterialSpec.getClientCipherKey();
        SecretKey serverCipherKey = tlsKeyMaterialSpec.getServerCipherKey();
        Assert.assertEquals(ENC_CIPHER_KEY_LEN, clientCipherKey.getEncoded().length);
        Assert.assertEquals(ENC_CIPHER_KEY_LEN, serverCipherKey.getEncoded().length);
        // cipher key server mode
        SecretKey clientCipherKey1 = tlsKeyMaterialSpec1.getClientCipherKey();
        SecretKey serverCipherKey1 = tlsKeyMaterialSpec1.getServerCipherKey();
        Assert.assertEquals(ENC_CIPHER_KEY_LEN, clientCipherKey1.getEncoded().length);
        Assert.assertEquals(ENC_CIPHER_KEY_LEN, serverCipherKey1.getEncoded().length);
        checkCipherKey(clientCipherKey, clientCipherKey1);
        checkCipherKey(serverCipherKey, serverCipherKey1);

        // iv client mode
        IvParameterSpec clientIv = tlsKeyMaterialSpec.getClientIv();
        IvParameterSpec serverIv = tlsKeyMaterialSpec.getServerIv();
        Assert.assertEquals(IV_LEN, clientIv.getIV().length);
        Assert.assertEquals(IV_LEN, serverIv.getIV().length);
        // iv server mode
        IvParameterSpec clientIv1 = tlsKeyMaterialSpec1.getClientIv();
        IvParameterSpec serverIv1 = tlsKeyMaterialSpec1.getServerIv();
        Assert.assertEquals(IV_LEN, clientIv1.getIV().length);
        Assert.assertEquals(IV_LEN, serverIv1.getIV().length);
        Assert.assertArrayEquals(clientIv.getIV(), clientIv1.getIV());
        Assert.assertArrayEquals(serverIv.getIV(), serverIv1.getIV());
    }

    private static void checkMacKey(SecretKey clientMacKey, SecretKey serverMacKey) throws Exception {
        byte[] clientMac = mac(clientMacKey);
        byte[] serverMac = mac(serverMacKey);
        Assert.assertArrayEquals(clientMac, serverMac);
    }

    private static byte[] mac(SecretKey macKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSM3");
        mac.init(macKey);
        return mac.doFinal(MESSAGE.getBytes());
    }

    private static void checkCipherKey(SecretKey clientCipherKey, SecretKey serverCipherKey) throws Exception {
        byte[] data = MESSAGE.getBytes();
        byte[] encData = encrypt(clientCipherKey, data);
        byte[] decData = decrypt(serverCipherKey, encData);
        Assert.assertArrayEquals(data, decData);
    }

    private static byte[] encrypt(SecretKey cipherKey, byte[] data) throws Exception {
        System.out.println(new String(cipherKey.getEncoded()));
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(SecretKey cipherKey, byte[] encData) throws Exception {
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        return cipher.doFinal(encData);
    }

}
