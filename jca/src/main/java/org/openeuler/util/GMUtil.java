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

import org.openeuler.BGMJCEConfig;
import org.openeuler.SM2P256V1Point;
import org.openeuler.SM2PreComputeInfo;
import org.openeuler.legacy.LegacyGMUtil;
import org.openeuler.org.bouncycastle.SM2ParameterSpec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class GMUtil {

    private static final Set<String> SM2_CURVE_NAMES = new HashSet<>(
            Arrays.asList("sm2p256v1", "1.2.156.10197.1.301"));

    private static final EllipticCurve SM2_CURVE = new EllipticCurve(
            new ECFieldFp(
                    new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
            ),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
            new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16));

    public static boolean isSM2Curve(AlgorithmParameterSpec params) {
        if (params instanceof ECParameterSpec) {
            EllipticCurve curve = ((ECParameterSpec) params).getCurve();
            return isSM2Curve(curve);
        } else if (params instanceof ECGenParameterSpec) {
            ECGenParameterSpec genParameterSpec = (ECGenParameterSpec) params;
            return SM2_CURVE_NAMES.contains(genParameterSpec.getName());
        }
        return false;
    }

    public static boolean isSM2Curve(EllipticCurve curve) {
        return SM2_CURVE.equals(curve);
    }

    public static AlgorithmParameterSpec createSM2ParameterSpec(byte[] idBytes) {
        return BGMJCEConfig.useLegacy() ?
                LegacyGMUtil.createSM2ParameterSpec(idBytes) :
                new SM2ParameterSpec(idBytes);

    }

    /**
     * Convert a BigInteger to a byte array, ensuring it is exactly size long.
     *
     * @param bi  the BigInteger to be converted.
     * @param size the size
     * @return the resulting byte array.
     */
    public static byte[] bigIntegerToBytes(BigInteger bi, int size) {
        byte[] bytes = bi.toByteArray();
        if (bytes.length == size) {
            return bytes;
        }
        byte[] newArray = new byte[size];
        if (size < bytes.length) {
            System.arraycopy(bytes, bytes.length - newArray.length, newArray, 0, newArray.length);
        } else {
            System.arraycopy(bytes, 0, newArray, newArray.length - bytes.length, bytes.length);
        }
        return newArray;
    }

    /**
     * Check if elliptic curve point is on target elliptic curve
     *
     * @param ecPoint
     * @param curve
     * @return true or false
     */
    public static boolean checkECPoint(ECPoint ecPoint, EllipticCurve curve) {
        BigInteger p;
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


    public static ECPoint multiply(ECPoint ecPoint, int k, EllipticCurve curve) {
        return multiply(ecPoint, BigInteger.valueOf(k), curve);
    }

    public static ECPoint multiply(ECPoint ecPoint, BigInteger k, EllipticCurve curve) {
        if (ecPoint == ECPoint.POINT_INFINITY) {
            return ecPoint;
        }
        int size = curve.getField().getFieldSize();
        SM2PreComputeInfo info = SM2PreComputeUtil.getPreComputeInfo(ecPoint, size);
        SM2P256V1Point[] lookupTable = info.getLookupTable();
        int width = info.getWidth();

        int d = (size + width - 1) / width;

        SM2P256V1Point R = SM2P256V1Point.getPointInfinity();

        int fullComb = d * width;
        int[] K = Nat.fromBigInteger(fullComb, k);

        int top = fullComb - 1;
        for (int i = 0; i < d; ++i) {
            int secretIndex = 0;

            for (int j = top - i; j >= 0; j -= d) {
                int secretBit = K[j >>> 5] >>> (j & 0x1F);
                secretIndex ^= secretBit >>> 1;
                secretIndex <<= 1;
                secretIndex ^= secretBit;
            }
            R = add(twice(R), lookupTable[secretIndex]);
        }
        R = add(R, info.getOffset());
        return R.normalize();
    }

    public static ECPoint add(ECPoint p1, ECPoint p2) {
        if (p1 == ECPoint.POINT_INFINITY) {
            return p2;
        }
        if (p2 == ECPoint.POINT_INFINITY) {
            return p1;
        }
        return add(new SM2P256V1Point(p1), new SM2P256V1Point(p2)).normalize();
    }

    static SM2P256V1Point subtract(SM2P256V1Point p1, SM2P256V1Point p2) {
        return add(p1, p2.negate());
    }

    static SM2P256V1Point timesPow2(SM2P256V1Point p, int e) {
        SM2P256V1Point p2 = p;
        if (e < 0) {
            throw new IllegalArgumentException("'e' cannot be negative");
        }

        while (--e >= 0) {
            p2 = twice(p2);
        }
        return p2;
    }

    /**
     * U2 = lambda2
     * S2 = lambda5
     *
     * U1 = lambda1
     * S1 = lambda4
     *
     * H = U1 - U2 = lambda1 - lambda2 = lambda3
     * R = S1 - S2 = lambda4 - lambda5 = lambda6
     *
     * G = H^3 = (lambda3)^3
     *
     * V = H^2 * U1 = (lambda3)^2 * lambda1
     *
     * G = -H^3 = -(lambda3)^3
     * tt1 = S1 * G = lambda4 * (- (lambda3)^3)
     * G = 2*V + G = 2 * (lambda3^2 * lambda1) + (-(lambda3)^3 )
     *             = lambda3^2 (2 * lambda1 - lambda3)
     *             = lambda3^2 ( 2 * lambda1 - (lambda1 - lambda2))
     *             = lambda3^2 * (lambda1 + lambda2 )
     *             = lambda3^2 * lambda7
     *
     * X3 = R^2 - G = lambda6^2 -  lambda7 *(lambda3)^2
     * Y3 = (V - X3) * R + tt1  = (lambda1 * (lambda3)^2 - X3) * lambda6 + (lambda4 * (- (lambda3)^3))
     *                          = lambda6 * (lambda1 * (lambda3)^2 - X3) - lambda4 * (lambda3)^3
     * Z3 = H * Z1 * Z2 = lambda3 * Z1 * Z2 = Z1 * Z2 * lambda3
     */
    static SM2P256V1Point add(SM2P256V1Point p1, SM2P256V1Point p2) {
        if (p1.isInfinity()) {
            return p2;
        }
        if (p2.isInfinity()) {
            return p1;
        }
        if (p1.equals(p2)) {
            return twice(p1);
        }

        int[] X1 = p1.getX();
        int[] Y1 = p1.getY();
        int[] Z1 = p1.getZ();
        int[] X2 = p2.getX();
        int[] Y2 = p2.getY();
        int[] Z2 = p2.getZ();
        int c;
        int[] tt1 = Nat256.createExt();
        int[] t2 = Nat256.create();
        int[] t3 = Nat256.create();
        int[] t4 = Nat256.create();

        int[] U2, S2;
        boolean Z1IsOne = Nat256.isOne(Z1);
        if (Z1IsOne) {
            U2 = X2;
            S2 = Y2;
        } else {
            S2 = t3;
            SM2P256CurveUtil.square(Z1, S2);

            U2 = t2;
            SM2P256CurveUtil.multiply(S2, X2, U2);

            SM2P256CurveUtil.multiply(S2, Z1, S2);
            SM2P256CurveUtil.multiply(S2, Y2, S2);
        }


        int[] U1, S1;
        boolean Z2IsOne = Nat256.isOne(Z2);
        if (Z2IsOne) {
            U1 = X1;
            S1 = Y1;
        } else {
            S1 = t4;
            SM2P256CurveUtil.square(Z2, S1);

            U1 = tt1;
            SM2P256CurveUtil.multiply(S1, X1, U1);

            SM2P256CurveUtil.multiply(S1, Z2, S1);
            SM2P256CurveUtil.multiply(S1, Y1, S1);
        }

        int[] H = Nat256.create();
        SM2P256CurveUtil.subtract(U1, U2, H);

        int[] R = t2;
        SM2P256CurveUtil.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat256.isZero(H)) {
            if (Nat256.isZero(R)) {
                // this == b, i.e. this must be doubled
                return twice(p1);
            }

            // this == -b, i.e. the result is the point at infinity
            return SM2P256V1Point.getPointInfinity();
        }

        int[] HSquared = t3;
        SM2P256CurveUtil.square(H, HSquared);

        int[] G = Nat256.create();
        SM2P256CurveUtil.multiply(HSquared, H, G);

        int[] V = t3;
        SM2P256CurveUtil.multiply(HSquared, U1, V);

        SM2P256CurveUtil.negate(G, G);
        Nat256.mul(S1, G, tt1);

        c = Nat256.addBothTo(V, V, G);
        SM2P256CurveUtil.reduce32(c, G);

        int[] X3 = t4;
        SM2P256CurveUtil.square(R, X3);
        SM2P256CurveUtil.subtract(X3, G, X3);

        int[] Y3 = G;
        SM2P256CurveUtil.subtract(V, X3, Y3);
        SM2P256CurveUtil.multiplyAddToExt(Y3, R, tt1);
        SM2P256CurveUtil.reduce(tt1, Y3);

        int[] Z3 = H;
        if (!Z1IsOne) {
            SM2P256CurveUtil.multiply(Z3, Z1, Z3);
        }
        if (!Z2IsOne) {
            SM2P256CurveUtil.multiply(Z3, Z2, Z3);
        }
        return new SM2P256V1Point(X3, Y3, Z3);
    }

    /**
     * T = (Y1)^4
     * t2 = (Z1)^2
     * t1 = X1 - (Z1)^2
     * M = X1 + (Z1)^2
     * M = M * t1 = (X1)^2 - (Z1)^4
     * M = M + M + M = 3 * (X1)^2 - 3 *(Z1)^4 <==> Is it equivalent?  (3 *(X1^2) + a * (Z1)^4)  = lambda1
     * <p>
     * S = (X1 *(Y1)^2 )<< 2 = 4 * X1 * (Y1)^2 = lambda2
     * t1 = T << 3 = 8 * T = 8 * (Y1)^4 = lambda3
     * <p>
     * X3 = M^2 - 2 * S = (lambda1)^2 - 2 * lambda2
     * Y3 = (S - X3) * M - t1 = (lambda2 - X3) * lambda1 - lambda3 = lambda1 * (lambda2 - X3) - lambda3
     * Z3 = 2 * Y1 * Z1
     */
    private static SM2P256V1Point twice(SM2P256V1Point p1) {
        if (p1.isInfinity()) {
            return p1;
        }

        int[] Y1 = p1.getY();
        if (Nat256.isZero(Y1)) {
            return SM2P256V1Point.getPointInfinity();
        }
        int[] X1 = p1.getX();
        int[] Z1 = p1.getZ();

        int c;
        int[] t1 = Nat256.create();
        int[] t2 = Nat256.create();

        int[] Y1Squared = Nat256.create();
        SM2P256CurveUtil.square(Y1, Y1Squared);

        int[] T = Nat256.create();
        SM2P256CurveUtil.square(Y1Squared, T);

        int[] Z1Squared = Z1;
        boolean Z1IsOne = Nat256.isOne(Z1);
        if (!Z1IsOne) {
            Z1Squared = t2;
            SM2P256CurveUtil.square(Z1, Z1Squared);
        }

        SM2P256CurveUtil.subtract(X1, Z1Squared, t1);

        int[] M = t2;
        SM2P256CurveUtil.add(X1, Z1Squared, M);
        SM2P256CurveUtil.multiply(M, t1, M);
        c = Nat256.addBothTo(M, M, M);
        SM2P256CurveUtil.reduce32(c, M);

        int[] S = Y1Squared;
        SM2P256CurveUtil.multiply(Y1Squared, X1, S);
        c = Nat.shiftUpBits(8, S, 2, 0);
        SM2P256CurveUtil.reduce32(c, S);

        c = Nat.shiftUpBits(8, T, 3, 0, t1);
        SM2P256CurveUtil.reduce32(c, t1);

        int[] X3 = T;
        SM2P256CurveUtil.square(M, X3);
        SM2P256CurveUtil.subtract(X3, S, X3);
        SM2P256CurveUtil.subtract(X3, S, X3);

        int[] Y3 = S;
        SM2P256CurveUtil.subtract(S, X3, Y3);
        SM2P256CurveUtil.multiply(Y3, M, Y3);
        SM2P256CurveUtil.subtract(Y3, t1, Y3);

        int[] Z3 = M;
        SM2P256CurveUtil.twice(Y1, Z3);
        if (!Z1IsOne) {
            SM2P256CurveUtil.multiply(Z3, Z1, Z3);
        }
        return new SM2P256V1Point(X3, Y3, Z3);
    }
}
