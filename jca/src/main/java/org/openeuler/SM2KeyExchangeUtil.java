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

import org.openeuler.constant.GMConstants;
import org.openeuler.util.GMUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

/**
 * SM2 KeyExchange util
 */
public class SM2KeyExchangeUtil {
    private static boolean DEBUG = false;

    public static byte[] generateSharedSecret(byte[] localId, ECPrivateKey localPrivateKey, ECPublicKey localPublicKey,
                                              ECPrivateKey localTempPrivateKey, ECPublicKey localTempPublicKey,
                                              byte[] peerId, ECPublicKey peerPublicKey, ECPublicKey peerTempPublicKey,
                                              int secretLen, boolean useClientMode)
            throws IOException, NoSuchAlgorithmException {
        BigInteger rA = localTempPrivateKey.getS();

        // RA = [rA]*G
        ECPoint RA = localTempPublicKey.getW();
        BigInteger n = localPublicKey.getParams().getOrder();

        // w = ceil(ceil(log2(n)/2) -1
        int w = (int) Math.ceil((double) n.subtract(BigInteger.ONE).bitLength() / 2) - 1;
        BigInteger wk = BigInteger.ONE.shiftLeft(w);

        // x1 = 2^w + (x1 & (2^w - 1))
        BigInteger x1 = RA.getAffineX();
        x1 = wk.add(x1.and(wk.subtract(BigInteger.ONE)));

        // tA = (dA + x1 * rA) mod n
        BigInteger dA = localPrivateKey.getS();
        BigInteger tA = dA.add(x1.multiply(rA)).mod(n);

        // x2 = 2^w + (x2 & (2^w - 1))
        ECPoint RB = peerTempPublicKey.getW();
        BigInteger x2 = RB.getAffineX();
        x2 = wk.add(x2.and(wk.subtract(BigInteger.ONE)));

        // V = (PB + RB * x2) * (h * tA)
        BigInteger h = BigInteger.valueOf(localPublicKey.getParams().getCofactor());
        ECPoint PB = peerPublicKey.getW();
        EllipticCurve peerCurve = peerPublicKey.getParams().getCurve();
        ECPoint V = GMUtil.multiply(GMUtil.add(PB,
                                    GMUtil.multiply(RB, x2, peerCurve)),
                                    h.multiply(tA),
                                    peerCurve);

        BigInteger xV = V.getAffineX();
        BigInteger yV = V.getAffineY();

        MessageDigest messageDigest = MessageDigest.getInstance("SM3");
        byte[] ZA = generateZ(localId, localPublicKey, messageDigest);
        byte[] ZB = generateZ(peerId, peerPublicKey, messageDigest);

        // xv || yv || ZA || ZB
        byte[] bytes = concat(xV, yV, ZA, ZB, useClientMode);
        byte[] sharedSecret = KDF(bytes, secretLen, messageDigest);

        if (DEBUG) {
            System.out.println("xV = " + xV.toString(16));
            System.out.println("yV = " + yV.toString(16));
            System.out.println("ZA =" + new BigInteger(ZA).toString(16));
            System.out.println("ZB =" + new BigInteger(ZB).toString(16));
            System.out.println("(xv || yv || ZA || ZB) = " + Arrays.toString(bytes));
            System.out.println("sharedSecret = " + Arrays.toString(sharedSecret));
        }
        return sharedSecret;
    }

    /**
     * R = [r] * G
     *
     * @param publicKey
     * @param random
     * @return R
     */
    public static ECPoint generateR(ECPublicKey publicKey, BigInteger random) {
        ECPoint g = publicKey.getParams().getGenerator();
        return GMUtil.multiply(g, random, publicKey.getParams().getCurve());
    }

    public static BigInteger generateRandom(ECPublicKey publicKey, SecureRandom secureRandom) {
        BigInteger n = publicKey.getParams().getOrder();
        return generateRandom(n, secureRandom);
    }

    public static BigInteger generateRandom(BigInteger n, SecureRandom secureRandom) {
        BigInteger random;
        int len = n.bitLength() / 8;
        int iterationCount = 64;
        int iterationIndex = 0;
        while (true) {
            do {
                random = new BigInteger(n.bitLength(), secureRandom);
            } while (random.compareTo(n) >= 0 || BigInteger.ONE.equals(random));

            if (random.bitLength() / 8 == len) {
                iterationIndex++;
                continue;
            }
            if (iterationIndex >= iterationCount) {
                return random;
            }
        }
    }

    /**
     * Z = hash(
     * idLenBytes || idBytes ||
     * (32bytes)a || (32bytes) b ||  (32bytes)gX ||  (32bytes)gY ||  (32bytes)qX || (32bytes) qY)
     * )
     *
     * @param idBytes       id
     * @param publicKey     SM2 PublicKey
     * @param messageDigest SM3 digest
     * @return Z
     */
    public static byte[] generateZ(byte[] idBytes, ECPublicKey publicKey, MessageDigest messageDigest) {
        if (idBytes == null) {
            idBytes = GMConstants.DEFAULT_ID;
        }
        int idBitsLen = idBytes.length * 8;
        EllipticCurve curve = publicKey.getParams().getCurve();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();

        ECPoint g = publicKey.getParams().getGenerator();
        BigInteger gX = g.getAffineX();
        BigInteger gY = g.getAffineY();

        ECPoint q = publicKey.getW();
        BigInteger qX = q.getAffineX();
        BigInteger qY = q.getAffineY();

        int m = 0;
        if (curve.getField() instanceof ECFieldF2m) {
            m = ((ECFieldF2m) curve.getField()).getM();
        }

        BigInteger[] elements = new BigInteger[]{a, b, gX, gY, qX, qY};
        byte[] idLenBytes = new byte[]{(byte) (idBitsLen >> 8), (byte) idBitsLen};
        messageDigest.update(idLenBytes);
        messageDigest.update(idBytes);
        for (BigInteger element : elements) {
            messageDigest.update(convertToBytes(element, m));
        }
        return messageDigest.digest();
    }

    public static byte[] KDF(byte[] bytes, int keyLength, MessageDigest messageDigest) {
        int digestLength = messageDigest.getDigestLength();
        int hashBitsLen = digestLength * 8;

        byte[] keyBytes = new byte[keyLength];
        int keyBitsLen = keyLength * 8;

        int count = keyBitsLen / hashBitsLen + 1;
        byte[] iBytes = new byte[4];
        for (int i = 1; i < count; i++) {
            messageDigest.update(bytes);
            intToBytes(iBytes, i);
            messageDigest.update(iBytes);
            byte[] digestBytes = messageDigest.digest();
            System.arraycopy(digestBytes, 0,
                    keyBytes, (i - 1) * digestLength, digestLength);
        }

        int remainBits = keyBitsLen % hashBitsLen;
        if (remainBits != 0) {
            messageDigest.update(bytes);
            intToBytes(iBytes, count);
            messageDigest.update(iBytes);
            byte[] digestBytes = messageDigest.digest();
            System.arraycopy(digestBytes, 0,
                    keyBytes, (count - 1) * digestLength, remainBits / 8);
        }
        return keyBytes;
    }

    private static void intToBytes(byte[] iBytes, int num) {
        iBytes[3] = (byte) num;
        iBytes[2] = (byte) ((num >> 8) & 0xff);
        iBytes[1] = (byte) ((num >> 16) & 0xff);
        iBytes[0] = (byte) ((num >> 24) & 0xff);
    }

    private static byte[] concat(BigInteger xV, BigInteger yV, byte[] ZA, byte[] ZB, boolean useClientMode)
            throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(convertToBytes(xV));
        outputStream.write(convertToBytes(yV));
        if (useClientMode) { // client is receiver
            outputStream.write(ZB);
            outputStream.write(ZA);
        } else { // server is sender
            outputStream.write(ZA);
            outputStream.write(ZB);
        }
        return outputStream.toByteArray();
    }

    /**
     * BigInteger convert to byte[]
     * If bytes.length is less than 32 , the preceding 32-bytes.length bytes are filled with 0.
     * The format is as follows:
     * 0..0 bytes[1]...bytes[bytes.length-1]
     * <p>
     * If the length is greater than or equal to 32 ,keep the last 32-bit byte.
     * The format is as follows:
     * bytes[bytes.length-32] ... bytes[bytes.length-1]
     *
     * @param val BigInteger
     * @return byte[]
     */
    private static byte[] convertToBytes(BigInteger val) {
        byte[] bytes = val.toByteArray();
        byte[] newBytes = new byte[32];
        if (bytes.length < 32) {
            System.arraycopy(bytes, 0, newBytes, 32 - bytes.length, bytes.length);
        } else {
            System.arraycopy(bytes, bytes.length - 32, newBytes, 0, newBytes.length);
        }
        return newBytes;
    }

    private static byte[] convertToBytes(BigInteger val, int m) {
        if (m == 0) {
            return convertToBytes(val);
        }
        int size = m % 8 == 0 ? m / 8 : m / 8 + 1;
        byte[] bytes = convertToBytes(val);
        if (bytes.length == size) {
            return bytes;
        }

        byte[] newBytes = new byte[size];
        if (bytes.length < size) {
            // todo
        } else {
            System.arraycopy(bytes, 0, newBytes, size - bytes.length, bytes.length);
        }
        return newBytes;
    }

    /**
     * Generate public key by ECPrivateKey
     *
     * @param privateKey
     * @return ECPublicKey
     * @throws InvalidKeyException
     */
    public static ECPublicKey generatePublicKey(ECPrivateKey privateKey) throws InvalidKeyException {
        ECParameterSpec parameters = privateKey.getParams();

        // P = G * d
        BigInteger d = privateKey.getS();
        ECPoint G = parameters.getGenerator();
        ECPoint P = GMUtil.multiply(G, d, parameters.getCurve());
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(P, parameters);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm());
            return (ECPublicKey) keyFactory.generatePublic(ecPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }
}
