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

package org.openeuler.util;

import sun.security.util.ECKeySizeParameterSpec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

public class ECUtil {

    public static final BigInteger THREE = new BigInteger("3");

    /**
     * Elliptic curve addition
     *
     * @param ecP1
     * @param ecP2
     * @param curve
     * @return The resulting point after adding two points together
     */
    public static ECPoint add(ECPoint ecP1, ECPoint ecP2, EllipticCurve curve) {
        if (ecP1 == null || ecP2 == null) {
            return null;
        }
        if (ecP1.equals(ECPoint.POINT_INFINITY) && ecP2.equals(ECPoint.POINT_INFINITY)) {
            return ECPoint.POINT_INFINITY;
        } else if (ecP1.equals(ECPoint.POINT_INFINITY)) {
            return new ECPoint(ecP2.getAffineX(), ecP2.getAffineY());
        } else if (ecP2.equals(ECPoint.POINT_INFINITY)) {
            return new ECPoint(ecP1.getAffineX(), ecP1.getAffineY());
        }

        BigInteger p = null;
        if (curve.getField() instanceof ECFieldFp) {
            p = ((ECFieldFp) curve.getField()).getP();
        } else {
            throw new IllegalArgumentException("Unsupported finite field type or finite field type parameter error");
        }

        BigInteger lambda;
        if (ecP1.getAffineX().subtract(ecP2.getAffineX()).mod(p).compareTo(BigInteger.ZERO) == 0) {
            if (ecP1.getAffineY().subtract(ecP2.getAffineY()).mod(p).compareTo(BigInteger.ZERO) == 0) {
                // lambda = (3x1^2 + a) / (2y1)
                BigInteger numerator = ecP1.getAffineX().multiply(ecP1.getAffineX()).multiply(THREE).add(curve.getA());
                BigInteger denominator = ecP1.getAffineY().add(ecP1.getAffineY());
                lambda = numerator.multiply(denominator.modInverse(p));
            } else {
                // lambda = infinity
                return ECPoint.POINT_INFINITY;
            }
        } else {
            // lambda = (y2 - y1) / (x2 - x1)
            BigInteger numerator = ecP2.getAffineY().subtract(ecP1.getAffineY());
            BigInteger denominator = ecP2.getAffineX().subtract(ecP1.getAffineX());
            lambda = numerator.multiply(denominator.modInverse(p));
        }

        // Now the easy part:
        // p3(x3, y3)
        // The result is p3(x3 = lambda^2 - x1 - x2, y3 = lambda(x1 - x3) - y1)
        BigInteger x3 = lambda.multiply(lambda).subtract(ecP1.getAffineX()).subtract(ecP2.getAffineX()).mod(p);
        BigInteger y3 = lambda.multiply(ecP1.getAffineX().subtract(x3)).subtract(ecP1.getAffineY()).mod(p);
        return new ECPoint(x3, y3);
    }

    /**
     * lliptic curve subtract
     *
     * @param p1
     * @param p2
     * @param curve
     * @return The resulting point after subtracting one point from another
     */
    public static ECPoint subtract(ECPoint p1, ECPoint p2, EllipticCurve curve) {
        if (p1 == null || p2 == null) return null;

        return add(p1, new ECPoint(p2.getAffineX(), p2.getAffineY().negate()), curve);
    }

    /**
     * Elliptic curve multiplication
     *
     * @param ecP
     * @param n
     * @param curve
     * @return The resulting point after adding n points together
     */
    public static ECPoint multiply(ECPoint ecP, BigInteger n, EllipticCurve curve) {
        if (ecP.equals(ECPoint.POINT_INFINITY)) {
            return ECPoint.POINT_INFINITY;
        }

        ECPoint result = ECPoint.POINT_INFINITY;
        int bitLength = n.bitLength();
        for (int i = bitLength - 1; i >= 0; --i) {
            result = add(result, result, curve);
            if (n.testBit(i)) {
                result = add(result, ecP, curve);
            }
        }
        return result;
    }

    /**
     * Elliptic curve multiplication
     *
     * @param ecP
     * @param n
     * @param curve
     * @return The resulting point after adding n points together
     */
    public static ECPoint multiply(ECPoint ecP, int n, EllipticCurve curve) {
        return multiply(ecP, BigInteger.valueOf(n), curve);
    }

    /**
     * Decode a point on an elliptic curve
     *
     * @param data
     * @param curve
     * @return The resulting byte array after decoding
     * @throws IOException
     */
    public static ECPoint decodePoint(byte[] data, EllipticCurve curve)
            throws IOException {
        if ((data.length == 0) || (data[0] != 4)) {
            throw new IOException("Only uncompressed point format supported");
        }
        // Per ANSI X9.62, an encoded point is a 1 byte type followed by
        // ceiling(log base 2 field-size / 8) bytes of x and the same of y.
        int n = (data.length - 1) / 2;
        if (n != ((curve.getField().getFieldSize() + 7) >> 3)) {
            throw new IOException("Point does not match field size");
        }

        byte[] xb = Arrays.copyOfRange(data, 1, 1 + n);
        byte[] yb = Arrays.copyOfRange(data, n + 1, n + 1 + n);

        return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
    }

    /**
     * Encode a point on an elliptic curve
     *
     * @param point
     * @param curve
     * @return The resulting byte array after encoding
     */
    public static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
        // get field size in bytes (rounding up)
        int n = (curve.getField().getFieldSize() + 7) >> 3;
        byte[] xb = trimZeroes(point.getAffineX().toByteArray());
        byte[] yb = trimZeroes(point.getAffineY().toByteArray());
        if ((xb.length > n) || (yb.length > n)) {
            throw new RuntimeException
                    ("Point coordinates do not match field size");
        }
        byte[] b = new byte[1 + (n << 1)];
        b[0] = 4; // uncompressed
        System.arraycopy(xb, 0, b, n - xb.length + 1, xb.length);
        System.arraycopy(yb, 0, b, b.length - yb.length, yb.length);
        return b;
    }

    /**
     * Trim invalid bytes from a byte array
     *
     * @param b
     * @return The resulting byte array after trimming
     */
    public static byte[] trimZeroes(byte[] b) {
        int i = 0;
        while ((i < b.length - 1) && (b[i] == 0)) {
            i++;
        }
        if (i == 0) {
            return b;
        }

        return Arrays.copyOfRange(b, i, b.length);
    }

    /**
     * Get EC AlgorithmParameters
     *
     * @param p
     * @return EC AlgorithmParameters
     */
    public static AlgorithmParameters getECParameters(Provider p) {
        try {
            if (p != null) {
                return AlgorithmParameters.getInstance("EC", p);
            }

            return AlgorithmParameters.getInstance("EC");
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
    }

    /**
     * Get ECParameterSpec
     *
     * @param p
     * @param spec
     * @return ECParameterSpec
     */
    public static ECParameterSpec getECParameterSpec(Provider p,
                                                     ECParameterSpec spec) {
        AlgorithmParameters parameters = getECParameters(p);

        try {
            parameters.init(spec);
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException ipse) {
            return null;
        }
    }

    /**
     * Get ECParameterSpec by name
     *
     * @param p
     * @param name
     * @return ECParameterSpec
     */
    public static ECParameterSpec getECParameterSpec(Provider p, String name) {
        AlgorithmParameters parameters = getECParameters(p);

        try {
            parameters.init(new ECGenParameterSpec(name));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException ipse) {
            return null;
        }
    }

    /**
     * Check if elliptic curve point is on target elliptic curve
     *
     * @param ecPoint
     * @param curve
     * @return true or false
     */
    public static boolean checkECPoint(ECPoint ecPoint, EllipticCurve curve) {
        BigInteger p = null;
        if (curve.getField() instanceof ECFieldFp) {
            p = ((ECFieldFp) curve.getField()).getP();
        } else {
            throw new IllegalArgumentException("Unsupported finite field type or finite field type parameter error");
        }

        BigInteger x = ecPoint.getAffineX();
        BigInteger y = ecPoint.getAffineY();

        BigInteger y_2 = y.pow(2).mod(p);
        BigInteger x_3 = x.pow(3).mod(p);
        BigInteger ax = curve.getA().multiply(x).mod(p);
        BigInteger b = curve.getB().mod(p);
        return y_2.equals(x_3.add(ax).add(b).mod(p));
    }

    /**
     * Determine if two ECParameterSpec objects are equal
     *
     * @param spec1
     * @param spec2
     * @return true or false
     */
    public static boolean equals(ECParameterSpec spec1, ECParameterSpec spec2) {
        if (spec1 == spec2) {
            return true;
        }

        if (spec1 == null || spec2 == null) {
            return false;
        }
        return (spec1.getCofactor() == spec2.getCofactor() &&
                spec1.getOrder().equals(spec2.getOrder()) &&
                spec1.getCurve().equals(spec2.getCurve()) &&
                spec1.getGenerator().equals(spec2.getGenerator()));
    }
}
