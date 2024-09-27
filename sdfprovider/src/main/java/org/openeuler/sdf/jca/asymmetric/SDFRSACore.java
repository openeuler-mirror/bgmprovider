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

import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;
import org.openeuler.sdf.wrapper.SDFRSACipherNative;
import sun.security.rsa.RSACore;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;
import sun.security.rsa.RSAUtil.KeyType;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.D;
import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.E;
import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.M;
import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.PRIME_COEFF;
import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.PRIME_EXPONENT_P;
import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.PRIME_EXPONENT_Q;
import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.PRIME_P;
import static org.openeuler.sdf.jca.asymmetric.SDFRSAKeyParamIndex.PRIME_Q;

public class SDFRSACore {

    public static final int ExRSAref_MAX_LEN = 512;
    public static final int ExRSAref_MAX_PLEN = 256;

    public static RSAPublicKey translateToRSAPublicKey(KeyType type, AlgorithmParameterSpec params, byte[][] keyParams)
            throws InvalidKeyException {
        return RSAPublicKeyImpl.newKey(
                type,
                params,
                new BigInteger(1, keyParams[M.getIndex()]),
                new BigInteger(1, keyParams[E.getIndex()]));
    }

    public static RSAPrivateKey translateToRSAPrivateKey(KeyType type, AlgorithmParameterSpec params, byte[][] keyParams)
            throws InvalidKeyException {
        return RSAPrivateCrtKeyImpl.newKey(
                type,
                params,
                new BigInteger(1, keyParams[M.getIndex()]),
                new BigInteger(1, keyParams[E.getIndex()]),
                new BigInteger(1, keyParams[D.getIndex()]),
                new BigInteger(1, keyParams[PRIME_P.getIndex()]),
                new BigInteger(1, keyParams[PRIME_Q.getIndex()]),
                new BigInteger(1, keyParams[PRIME_EXPONENT_P.getIndex()]),
                new BigInteger(1, keyParams[PRIME_EXPONENT_Q.getIndex()]),
                new BigInteger(1, keyParams[PRIME_COEFF.getIndex()])
        );
    }

    public static byte[][] translateToRSAPublicKeyParams(RSAPublicKey publicKey) {
        byte[] m = toByteArray(publicKey.getModulus(), ExRSAref_MAX_LEN);
        byte[] e = toByteArray(publicKey.getPublicExponent(), ExRSAref_MAX_LEN);
        return new byte[][]{m, e};
    }

    public static byte[][] translateToRSAPrivateKeyParams(RSAPrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey)) {
            throw new InvalidParameterException("Only support RSAPrivateCrtKey");
        }
        RSAPrivateCrtKey rsaCrtKey = (RSAPrivateCrtKey) privateKey;
        byte[] m = toByteArray(rsaCrtKey.getModulus(), ExRSAref_MAX_LEN);
        byte[] d = toByteArray(rsaCrtKey.getPrivateExponent(), ExRSAref_MAX_LEN);
        byte[] e = toByteArray(rsaCrtKey.getPublicExponent(), ExRSAref_MAX_LEN);
        byte[] p = toByteArray(rsaCrtKey.getPrimeP(), ExRSAref_MAX_PLEN);
        byte[] q = toByteArray(rsaCrtKey.getPrimeQ(), ExRSAref_MAX_PLEN);
        byte[] pe = toByteArray(rsaCrtKey.getPrimeExponentP(), ExRSAref_MAX_PLEN);
        byte[] qe = toByteArray(rsaCrtKey.getPrimeExponentQ(), ExRSAref_MAX_PLEN);
        byte[] coeff = toByteArray(rsaCrtKey.getCrtCoefficient(), ExRSAref_MAX_PLEN);
        return new byte[][]{m, e, d, p, q, pe, qe, coeff};
    }

    /**
     * Perform an RSA public key operation.
     */
    public static byte[] rsa(byte[] msg, RSAPublicKey key) {
        byte[][] pubKeyParams = translateToRSAPublicKeyParams(key);
        int bits = key.getModulus().bitLength();
        SDFSession session = SDFSessionManager.getInstance().getSession();
        byte[] encryptedData;
        try {
            encryptedData = SDFRSACipherNative.nativeEncrypt(
                    session.getAddress(),
                    bits,
                    pubKeyParams,
                    msg
            );
        } catch (SDFException e) {
            throw new SDFRuntimeException(e);
        } finally {
            SDFSessionManager.getInstance().releaseSession(session);
        }
        return encryptedData;
    }

    /**
     * Perform an RSA private key operation. Uses CRT if the key is a
     * CRT key.
     */
    public static byte[] rsa(byte[] msg, RSAPrivateKey key) {
        byte[][] priKeyParams = translateToRSAPrivateKeyParams(key);
        int bits = key.getModulus().bitLength();
        SDFSession session = SDFSessionManager.getInstance().getSession();
        byte[] decryptedData;
        try {
            decryptedData = SDFRSACipherNative.nativeDecrypt(
                    session.getAddress(),
                    bits,
                    priKeyParams,
                    msg
            );
        } catch (SDFException e) {
            throw new SDFRuntimeException(e);
        } finally {
            SDFSessionManager.getInstance().releaseSession(session);
        }
        return decryptedData;
    }

    /**
     * Return the encoding of this BigInteger that is exactly len bytes long.
     * Prefix/strip off leading 0x00 bytes if necessary.
     * Precondition: bi must fit into len bytes
     */
    private static byte[] toByteArray(BigInteger bi, int len) {
        byte[] b = bi.toByteArray();
        int n = b.length;
        if (n == len) {
            return b;
        }
        // BigInteger prefixed a 0x00 byte for 2's complement form, remove it
        if ((n == len + 1) && (b[0] == 0)) {
            byte[] t = new byte[len];
            System.arraycopy(b, 1, t, 0, len);
            Arrays.fill(b, (byte) 0);
            return t;
        }
        // must be smaller
        assert (n < len);
        byte[] t = new byte[len];
        System.arraycopy(b, 0, t, (len - n), n);
        Arrays.fill(b, (byte) 0);
        return t;
    }

    //
    public static byte[] prefixZero(byte[] b, int ofs , int len) {
        if (ofs == 0 && b.length == len) {
            return b;
        } else {
            byte[] t = new byte[b.length];
            System.arraycopy(b, ofs, t, t.length - len, len);
            return t;
        }
    }

}
