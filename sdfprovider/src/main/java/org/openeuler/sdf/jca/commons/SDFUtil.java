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

import org.openeuler.sdf.commons.key.SDFEncryptKey;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECPrivateKeyImpl;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static org.openeuler.sdf.commons.constant.SDFConstant.ENC_SM2_PRIVATE_KEY_SIZE;

public class SDFUtil {
    /**
     * Return the passed in value as an unsigned byte array of the specified length, padded with
     * leading zeros as necessary..
     *
     * @param length the fixed length of the result
     * @param value  the value to be converted.
     * @return a byte array padded to a fixed length with leading zeros.
     */
    public static byte[] asUnsignedByteArray(int length, BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }

        int start = (bytes[0] == 0 && bytes.length != 1) ? 1 : 0;
        int count = bytes.length - start;

        if (count > length) {
            throw new IllegalArgumentException("standard length exceeded for value");
        }

        byte[] tmp = new byte[length];
        System.arraycopy(bytes, start, tmp, tmp.length - count, count);
        return tmp;
    }

    public static byte[] getPrivateKeyBytes(PrivateKey privateKey) {
        if(!(privateKey instanceof SDFECPrivateKeyImpl)) {
            throw new IllegalArgumentException("only support EncryptKey");
        }
        int size;
        if(((SDFEncryptKey) privateKey).isEncKey()) {
            size = ENC_SM2_PRIVATE_KEY_SIZE;
        } else {
            size = (((SDFECPrivateKeyImpl) privateKey).getParams().getCurve().getField().getFieldSize() + 7) / 8;
        }
        return asUnsignedByteArray(size, ((SDFECPrivateKeyImpl) privateKey).getS());
    }

    public static Object[] getPublicKeyAffineXYBytes(ECPublicKey publicKey) {
        int size = (publicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        ECPoint w = publicKey.getW();
        return new Object[]{
                asUnsignedByteArray(size, w.getAffineX()),
                asUnsignedByteArray(size, w.getAffineY()),
        };
    }


    // convert sm2 encrypted parameters to SM2Cipher struct bytes
    public static byte[] encodeECCCipher(SDFSM2CipherMode outputMode, byte[][] sm2CipherParams) throws IOException {
        BigInteger x = new BigInteger(1, sm2CipherParams[0]);
        BigInteger y = new BigInteger(1, sm2CipherParams[1]);

        DerOutputStream out = new DerOutputStream();
        out.putInteger(x);
        out.putInteger(y);
        if (outputMode == SDFSM2CipherMode.C1C3C2) {
            out.putOctetString(sm2CipherParams[3]);
            out.putOctetString(sm2CipherParams[2]);
        } else if (outputMode == SDFSM2CipherMode.C1C2C3) {
            out.putOctetString(sm2CipherParams[2]);
            out.putOctetString(sm2CipherParams[3]);
        }
        DerValue result = new DerValue(DerValue.tag_Sequence, out.toByteArray());
        return result.toByteArray();
    }

    // convert SM2Cipher struct bytes to sm2 encrypted parameters
    public static byte[][] decodeECCCipher(SDFSM2CipherMode outputMode, byte[] in, int curveLength) throws IOException {
        DerInputStream inDer = new DerInputStream(in, 0, in.length, false);
        DerValue[] values = inDer.getSequence(2);
        // check number of components in the read sequence
        // and trailing data
        if ((values.length != 4) || (inDer.available() != 0)) {
            throw new IOException("Invalid encoding for signature");
        }

        BigInteger x = values[0].getPositiveBigInteger();
        BigInteger y = values[1].getPositiveBigInteger();

        byte[] c1x = SDFUtil.asUnsignedByteArray((curveLength + 7) / 8, x);
        byte[] c1y = SDFUtil.asUnsignedByteArray((curveLength + 7) / 8, y);

        byte[] c2, c3;
        if (outputMode == SDFSM2CipherMode.C1C3C2) {
            c3 = values[2].getOctetString();
            c2 = values[3].getOctetString();
        } else {
            c2 = values[2].getOctetString();
            c3 = values[3].getOctetString();
        }
        return new byte[][]{
                c1x,
                c1y,
                c2,
                c3
        };
    }
}
