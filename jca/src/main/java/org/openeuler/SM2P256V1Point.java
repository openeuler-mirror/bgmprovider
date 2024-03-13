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

package org.openeuler;

import org.openeuler.util.Nat256;
import org.openeuler.util.SM2P256CurveUtil;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class SM2P256V1Point {
    private final int[] x;
    private final int[] y;
    private final int[] z;

    private static final SM2P256V1Point POINT_INFINITY = new SM2P256V1Point();

    private SM2P256V1Point() {
        this.x = null;
        this.y = null;
        this.z = Nat256.fromBigInteger(BigInteger.ZERO);
    }

    public SM2P256V1Point(int[] x, int[] y, int[] z) {
        if (x == null || y == null || z == null) {
            throw new NullPointerException("affine coordinate x , y or z is null");
        }
        this.x = x;
        this.y = y;
        this.z = z;
    }

    public SM2P256V1Point(ECPoint point) {
        if (point == null) {
            throw new NullPointerException("point is null");
        }
        if (point.getAffineX() == null || point.getAffineY() == null) {
            throw new NullPointerException("affine coordinate x , y is null");
        }
        this.x = Nat256.fromBigInteger(point.getAffineX());
        this.y = Nat256.fromBigInteger(point.getAffineY());
        this.z = Nat256.fromBigInteger(BigInteger.ONE);
    }

    public int[] getX() {
        return x;
    }

    public int[] getY() {
        return y;
    }

    public int[] getZ() {
        return z;
    }

    public boolean isInfinity() {
        return this.x == null || this.y == null || BigInteger.ZERO.equals(Nat256.toBigInteger(this.z));
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (this == POINT_INFINITY) {
            return false;
        }
        if (obj instanceof SM2P256V1Point) {
            SM2P256V1Point point = (SM2P256V1Point) obj;
            return Arrays.equals(this.x, point.x) && Arrays.equals(this.y, point.y) && Arrays.equals(this.z, point.z);
        }
        return false;
    }

    @Override
    public int hashCode() {
        if (this == POINT_INFINITY) return 0;
        return Arrays.hashCode(x) << 5 + Arrays.hashCode(y);
    }

    public SM2P256V1Point negate() {
        if (this.isInfinity()) {
            return this;
        }
        int[] negateY = Nat256.create();
        SM2P256CurveUtil.negate(this.y, negateY);
        return new SM2P256V1Point(this.x, negateY, this.getZ());
    }

    public static SM2P256V1Point getPointInfinity() {
        return POINT_INFINITY;
    }

    public ECPoint normalize() {
        int[] zInv = Nat256.create();
        SM2P256CurveUtil.inv(this.z, zInv);
        int[] zInv2 = Nat256.create();
        SM2P256CurveUtil.square(zInv, zInv2);
        int[] zInv3 = Nat256.create();
        SM2P256CurveUtil.multiply(zInv, zInv2, zInv3);

        int[] x2 = Nat256.create();
        SM2P256CurveUtil.multiply(this.x, zInv2, x2);

        int[] y2 = Nat256.create();
        SM2P256CurveUtil.multiply(this.y, zInv3, y2);

        BigInteger x = Nat256.toBigInteger(x2);
        BigInteger y = Nat256.toBigInteger(y2);
        return new SM2Point(x, y);
    }
}
