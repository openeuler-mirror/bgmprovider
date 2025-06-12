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

package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.util.SDFTestUtil;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

public class SDFSM2TestUtil {
    public static KeyPair generateKeyPair(boolean isEncKey) throws Exception {
        return generateKeyPair(isEncKey, null);
    }

    public static KeyPair generateKeyPair(boolean isEncKey, Provider provider) throws Exception {
        KeyPairGenerator keyPairGenerator;
        if (provider != null) {
            keyPairGenerator = KeyPairGenerator.getInstance("SM2", provider);
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance("SM2");
        }
        if (isEncKey) {
            keyPairGenerator.initialize(new SDFSM2GenParameterSpec(
                    SDFTestUtil.getTestKekId(),
                    SDFTestUtil.getTestRegionId(),
                    SDFTestUtil.getTestCdpId(),
                    SDFTestUtil.getTestPin(),
                    "sm2p256v1"));
        }
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encrypt(Provider provider, Key publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2", provider);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    public static byte[] encrypt(Key publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    public static byte[] decrypt(Key privateKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    public static byte[] decrypt(Provider provider, Key privateKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("SM2", provider);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    public static byte[] sign(Provider provider, PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = SDFTestUtil.getSignature("SM3withSM2", provider);
        signature.initSign(privateKey);
        if (data != null) {
            signature.update(data);
        }
        System.out.println("sign-provider: " + signature.getProvider());
        return signature.sign();
    }

    public static byte[] sign(Provider provider, PrivateKey privateKey, byte[] data, int offset, int len)
            throws Exception {
        Signature signature = SDFTestUtil.getSignature("SM3withSM2", provider);
        signature.initSign(privateKey);
        if (data != null) {
            signature.update(data, offset, len);
        }
        System.out.println("sign-provider: " + signature.getProvider());
        return signature.sign();
    }

    public static byte[] sign(Provider provider, PrivateKey privateKey, ByteBuffer byteBuffer) throws Exception {
        Signature signature = SDFTestUtil.getSignature("SM3withSM2", provider);
        signature.initSign(privateKey);
        if (byteBuffer != null) {
            signature.update(byteBuffer);
        }
        System.out.println("sign-provider: " + signature.getProvider());
        return signature.sign();
    }


    public static boolean verify(Provider provider, PublicKey publicKey, byte[] data, byte[] signData) throws Exception {
        Signature signature = SDFTestUtil.getSignature("SM3withSM2", provider);
        signature.initVerify(publicKey);
        if (data != null) {
            signature.update(data);
        }
        System.out.println("verify-provider: " + signature.getProvider());
        return signature.verify(signData);
    }

    public static boolean verify(Provider provider, PublicKey publicKey, byte[] data, int offset, int len,
                                 byte[] signData) throws Exception {
        Signature signature = SDFTestUtil.getSignature("SM3withSM2", provider);
        signature.initVerify(publicKey);
        if (data != null) {
            signature.update(data, offset, len);
        }
        System.out.println("verify-provider: " + signature.getProvider());
        return signature.verify(signData);
    }

    public static boolean verify(Provider provider, PublicKey publicKey, ByteBuffer byteBuffer, byte[] signData)
            throws Exception {
        Signature signature = SDFTestUtil.getSignature("SM3withSM2", provider);
        signature.initVerify(publicKey);
        if (byteBuffer != null) {
            signature.update(byteBuffer);
        }
        System.out.println("verify-provider: " + signature.getProvider());
        return signature.verify(signData);
    }

}
