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

package org.openeuler.sdf.jsse.commons;

import org.openeuler.sdf.jca.commons.SDFUtil;
import org.openeuler.sdf.wrapper.SDFSM2KeyPairGeneratorNative;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

public class SDFKeyExchangeUtil {
    /**
     * Generate public key by ECPrivateKey
     *
     * @param privateKey
     * @return ECPublicKey
     * @throws InvalidKeyException
     */
    public static ECPublicKey generatePublicKey(ECPrivateKey privateKey) throws InvalidKeyException {
        ECParameterSpec parameters = privateKey.getParams();

        ECPoint P;
        byte[][] keys;
        try {
            keys = SDFSM2KeyPairGeneratorNative.nativeGeneratePublicKey(SDFUtil.getPrivateKeyBytes(privateKey));
        } catch (Exception e) {
            throw new RuntimeException("SDFSM2Signature failed. unable to generate PublicKey", e);
        }

        /**
         * // SM2 Key index.
         * typedef enum ECDHKeyIndex {
         *     ecdhWX = 0,
         *     ecdhWY,
         *     ecdhS
         * } ECDHKeyIndex;
         */
        BigInteger wX = new BigInteger(1, keys[0]);
        BigInteger wY = new BigInteger(1, keys[1]);
        P= new ECPoint(wX, wY);

        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(P, parameters);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm());
            return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }
}
