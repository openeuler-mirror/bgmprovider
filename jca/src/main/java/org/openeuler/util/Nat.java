package org.openeuler.util;

import java.math.BigInteger;
/**
 * The implementation of this class comes from
 * https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/math/raw/Nat.java
 */
public class Nat {
    private static final long M = 0xFFFFFFFFL;

    public static int[] create(int len) {
        return new int[len];
    }

    public static int equalTo(int len, int[] x, int y) {
        int d = x[0] ^ y;
        for (int i = 1; i < len; ++i) {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static int equalToZero(int len, int[] x) {
        int d = 0;
        for (int i = 0; i < len; ++i) {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static int[] fromBigInteger(int bits, BigInteger x) {
        if (x.signum() < 0 || x.bitLength() > bits) {
            throw new IllegalArgumentException();
        }

        int len = (bits + 31) >> 5;
        int[] z = create(len);

        for (int i = 0; i < len; ++i) {
            z[i] = x.intValue();
            x = x.shiftRight(32);
        }
        return z;
    }

    public static boolean gte(int len, int[] x, int[] y) {
        for (int i = len - 1; i >= 0; --i) {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if (x_i < y_i)
                return false;
            if (x_i > y_i)
                return true;
        }
        return true;
    }

    public static int shiftUpBit(int len, int[] x, int c, int[] z) {
        for (int i = 0; i < len; ++i) {
            int next = x[i];
            z[i] = (next << 1) | (c >>> 31);
            c = next;
        }
        return c >>> 31;
    }

    public static int shiftUpBits(int len, int[] z, int bits, int c) {
        for (int i = 0; i < len; ++i) {
            int next = z[i];
            z[i] = (next << bits) | (c >>> -bits);
            c = next;
        }
        return c >>> -bits;
    }

    public static int shiftUpBits(int len, int[] x, int bits, int c, int[] z) {
        for (int i = 0; i < len; ++i) {
            int next = x[i];
            z[i] = (next << bits) | (c >>> -bits);
            c = next;
        }
        return c >>> -bits;
    }


    public static int subFrom(int len, int[] x, int[] z) {
        long c = 0;
        for (int i = 0; i < len; ++i) {
            c += (z[i] & M) - (x[i] & M);
            z[i] = (int) c;
            c >>= 32;
        }
        return (int) c;
    }
}
