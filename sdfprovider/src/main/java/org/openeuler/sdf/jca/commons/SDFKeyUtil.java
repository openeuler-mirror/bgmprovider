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

package org.openeuler.sdf.jca.commons;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Key conversion Util
 */
public class SDFKeyUtil {

    // Valid AES key sizes in bytes.
    // NOTE: The values need to be listed in an *increasing* order
    // since DHKeyAgreement depends on this fact.
    private static final int[] AES_KEYSIZES = {16, 24, 32};

    // check if the specified length (in bytes) is a valid keysize for AES
    public static boolean isAESKeySizeValid(int len) {
        for (int i = 0; i < AES_KEYSIZES.length; i++) {
            if (len == AES_KEYSIZES[i]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Construct a public key from its encoding.
     *
     * @param encodedKey          the encoding of a public key.
     * @param encodedKeyAlgorithm the algorithm the encodedKey is for.
     * @return a public key constructed from the encodedKey.
     */
    private static PublicKey constructPublicKey(byte[] encodedKey, String encodedKeyAlgorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        PublicKey key;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            key = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("No provider found for " + encodedKeyAlgorithm + " KeyFactory");
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot construct public key", e);
        }
        return key;
    }

    /**
     * Construct a private key from its encoding.
     *
     * @param encodedKey          the encoding of a private key.
     * @param encodedKeyAlgorithm the algorithm the wrapped key is for.
     * @return a private key constructed from the encodedKey.
     */
    private static PrivateKey constructPrivateKey(byte[] encodedKey,
                                                  String encodedKeyAlgorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        PrivateKey key = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            key = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("No provider found for " + encodedKeyAlgorithm + " KeyFactory");
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot construct private key", e);
        }
        return key;
    }

    /**
     * Construct a secret key from its encoding.
     *
     * @param encodedKey          the encoding of a secret key.
     * @param encodedKeyAlgorithm the algorithm the secret key is for.
     * @return a secret key constructed from the encodedKey.
     */
    private static SecretKey constructSecretKey(byte[] encodedKey, String encodedKeyAlgorithm) {
        return new SecretKeySpec(encodedKey, encodedKeyAlgorithm);
    }

    // Convert from byte array to private designated key
    public static Key constructKey(int keyType, byte[] encodedKey,
                                   String encodedKeyAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Key res = null;
        switch (keyType) {
            case Cipher.SECRET_KEY:
                res = constructSecretKey(encodedKey, encodedKeyAlgorithm);
                break;
            case Cipher.PRIVATE_KEY:
                res = constructPrivateKey(encodedKey, encodedKeyAlgorithm);
                break;
            case Cipher.PUBLIC_KEY:
                res = constructPublicKey(encodedKey, encodedKeyAlgorithm);
                break;
            default:
                throw new InvalidKeyException("Unknown keytype " + keyType);
        }
        return res;
    }
}