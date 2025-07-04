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

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

public class SDFRSATestUtil {

    public static KeyPair generateKeyPair(int keySize) throws Exception {
        return generateKeyPair(keySize, (Provider) null);
    }

    public static KeyPair generateKeyPair(int keySize, Provider provider) throws Exception {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator("RSA", provider);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeyPair(int keySize, String provider) throws Exception {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator("RSA", provider);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    private static KeyPairGenerator getKeyPairGenerator(String transformation, Provider provider) throws Exception {
        KeyPairGenerator keyPairGenerator;
        if (provider != null) {
            keyPairGenerator = KeyPairGenerator.getInstance(transformation, provider);
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(transformation);
        }
        return keyPairGenerator;
    }

    private static KeyPairGenerator getKeyPairGenerator(String transformation, String provider) throws Exception {
        KeyPairGenerator keyPairGenerator;
        if (provider != null) {
            keyPairGenerator = KeyPairGenerator.getInstance(transformation, provider);
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(transformation);
        }
        return keyPairGenerator;
    }

    public static byte[] encrypt(String transformation, Provider provider, PublicKey publicKey, byte[] data)
            throws Exception {
        Cipher cipher = getCipher(transformation, provider);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    public static byte[] encrypt(String transformation, String provider, PublicKey publicKey, byte[] data)
            throws Exception {
        Cipher cipher = getCipher(transformation, provider);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    public static byte[] decrypt(String transformation, Provider provider, PrivateKey privateKey, byte[] data)
            throws Exception {
        Cipher cipher = getCipher(transformation, provider);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    public static byte[] decrypt(String transformation, String provider, PrivateKey privateKey, byte[] data)
            throws Exception {
        Cipher cipher = getCipher(transformation, provider);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipher.update(data);
        return cipher.doFinal();
    }

    private static Cipher getCipher(String transformation, Provider provider) throws Exception {
        Cipher cipher;
        if (provider != null) {
            cipher = Cipher.getInstance(transformation, provider);
        } else {
            cipher = Cipher.getInstance(transformation);
        }
        return cipher;
    }

    private static Cipher getCipher(String transformation, String provider) throws Exception {
        Cipher cipher;
        if (provider != null) {
            cipher = Cipher.getInstance(transformation, provider);
        } else {
            cipher = Cipher.getInstance(transformation);
        }
        return cipher;
    }

    public static byte[] sign(String algorithm, String provider, PrivateKey privateKey, byte[] data)
            throws Exception {
        Signature signature = getSignature(algorithm, provider);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(String algorithm, String provider, PublicKey publicKey,
                                 byte[] data, byte[] signData) throws Exception {
        Signature signature = getSignature(algorithm, provider);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signData);
    }

    private static Signature getSignature(String algorithm, Provider provider) throws Exception {
        Signature signature;
        if (provider != null) {
            signature = Signature.getInstance(algorithm, provider);
        } else {
            signature = Signature.getInstance(algorithm);
        }
        return signature;
    }

    private static Signature getSignature(String algorithm, String provider) throws Exception {
        Signature signature;
        if (provider != null) {
            signature = Signature.getInstance(algorithm, provider);
        } else {
            signature = Signature.getInstance(algorithm);
        }
        return signature;
    }
}
