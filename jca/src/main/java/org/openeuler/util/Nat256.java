package org.openeuler.util;

import java.math.BigInteger;

/**
 * The implementation of this class comes from
 * https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/math/raw/Nat256.java
 */
public class Nat256 {
    private static final long M = 0xFFFFFFFFL;

    public static int add(int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < 8; i++) {
            c += (x[i] & M) + (y[i] & M);
            z[i] = (int) c;
            c >>>= 32;
        }
        return (int) c;
    }

    public static int addBothTo(int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < 8; i++) {
            c += (x[i] & M) + (y[i] & M) + (z[i] & M);
            z[i] = (int) c;
            c >>>= 32;
        }
        return (int) c;
    }


    public static int[] create() {
        return new int[8];
    }

    public static int[] createExt() {
        return new int[16];
    }

    public static int[] fromBigInteger(BigInteger x) {
        if (x.signum() < 0 || x.bitLength() > 256) {
            throw new IllegalArgumentException();
        }

        int[] z = create();

        for (int i = 0; i < 8; ++i) {
            z[i] = x.intValue();
            x = x.shiftRight(32);
        }
        return z;
    }

    public static boolean gte(int[] x, int[] y) {
        for (int i = 7; i >= 0; --i) {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if (x_i < y_i)
                return false;
            if (x_i > y_i)
                return true;
        }
        return true;
    }

    public static boolean isOne(int[] x) {
        if (x[0] != 1) {
            return false;
        }
        for (int i = 1; i < 8; ++i) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero(int[] x) {
        for (int i = 0; i < 8; ++i) {
            if (x[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static void mul(int[] x, int[] y, int[] zz) {
        long y_0 = y[0] & M;
        long y_1 = y[1] & M;
        long y_2 = y[2] & M;
        long y_3 = y[3] & M;
        long y_4 = y[4] & M;
        long y_5 = y[5] & M;
        long y_6 = y[6] & M;
        long y_7 = y[7] & M;

        {
            long c = 0, x_0 = x[0] & M;
            c += x_0 * y_0;
            zz[0] = (int) c;
            c >>>= 32;
            c += x_0 * y_1;
            zz[1] = (int) c;
            c >>>= 32;
            c += x_0 * y_2;
            zz[2] = (int) c;
            c >>>= 32;
            c += x_0 * y_3;
            zz[3] = (int) c;
            c >>>= 32;
            c += x_0 * y_4;
            zz[4] = (int) c;
            c >>>= 32;
            c += x_0 * y_5;
            zz[5] = (int) c;
            c >>>= 32;
            c += x_0 * y_6;
            zz[6] = (int) c;
            c >>>= 32;
            c += x_0 * y_7;
            zz[7] = (int) c;
            c >>>= 32;
            zz[8] = (int) c;
        }

        for (int i = 1; i < 8; ++i) {
            long c = 0, x_i = x[i] & M;
            c += x_i * y_0 + (zz[i + 0] & M);
            zz[i + 0] = (int) c;
            c >>>= 32;
            c += x_i * y_1 + (zz[i + 1] & M);
            zz[i + 1] = (int) c;
            c >>>= 32;
            c += x_i * y_2 + (zz[i + 2] & M);
            zz[i + 2] = (int) c;
            c >>>= 32;
            c += x_i * y_3 + (zz[i + 3] & M);
            zz[i + 3] = (int) c;
            c >>>= 32;
            c += x_i * y_4 + (zz[i + 4] & M);
            zz[i + 4] = (int) c;
            c >>>= 32;
            c += x_i * y_5 + (zz[i + 5] & M);
            zz[i + 5] = (int) c;
            c >>>= 32;
            c += x_i * y_6 + (zz[i + 6] & M);
            zz[i + 6] = (int) c;
            c >>>= 32;
            c += x_i * y_7 + (zz[i + 7] & M);
            zz[i + 7] = (int) c;
            c >>>= 32;
            zz[i + 8] = (int) c;
        }
    }

    public static int mulAddTo(int[] x, int[] y, int[] zz) {
        long y_0 = y[0] & M;
        long y_1 = y[1] & M;
        long y_2 = y[2] & M;
        long y_3 = y[3] & M;
        long y_4 = y[4] & M;
        long y_5 = y[5] & M;
        long y_6 = y[6] & M;
        long y_7 = y[7] & M;

        long zc = 0;
        for (int i = 0; i < 8; ++i) {
            long c = 0, x_i = x[i] & M;
            c += x_i * y_0 + (zz[i + 0] & M);
            zz[i + 0] = (int) c;
            c >>>= 32;
            c += x_i * y_1 + (zz[i + 1] & M);
            zz[i + 1] = (int) c;
            c >>>= 32;
            c += x_i * y_2 + (zz[i + 2] & M);
            zz[i + 2] = (int) c;
            c >>>= 32;
            c += x_i * y_3 + (zz[i + 3] & M);
            zz[i + 3] = (int) c;
            c >>>= 32;
            c += x_i * y_4 + (zz[i + 4] & M);
            zz[i + 4] = (int) c;
            c >>>= 32;
            c += x_i * y_5 + (zz[i + 5] & M);
            zz[i + 5] = (int) c;
            c >>>= 32;
            c += x_i * y_6 + (zz[i + 6] & M);
            zz[i + 6] = (int) c;
            c >>>= 32;
            c += x_i * y_7 + (zz[i + 7] & M);
            zz[i + 7] = (int) c;
            c >>>= 32;

            zc += c + (zz[i + 8] & M);
            zz[i + 8] = (int) zc;
            zc >>>= 32;
        }
        return (int) zc;
    }

    public static void square(int[] x, int[] zz) {
        long x_0 = x[0] & M;
        long zz_1;

        int c = 0, w;
        {
            int i = 7, j = 16;
            do {
                long xVal = (x[i--] & M);
                long p = xVal * xVal;
                zz[--j] = (c << 31) | (int) (p >>> 33);
                zz[--j] = (int) (p >>> 1);
                c = (int) p;
            }
            while (i > 0);

            {
                long p = x_0 * x_0;
                zz_1 = ((c << 31) & M) | (p >>> 33);
                zz[0] = (int) p;
                c = (int) (p >>> 32) & 1;
            }
        }

        long x_1 = x[1] & M;
        long zz_2 = zz[2] & M;

        {
            zz_1 += x_1 * x_0;
            w = (int) zz_1;
            zz[1] = (w << 1) | c;
            c = w >>> 31;
            zz_2 += zz_1 >>> 32;
        }

        long x_2 = x[2] & M;
        long zz_3 = zz[3] & M;
        long zz_4 = zz[4] & M;
        {
            zz_2 += x_2 * x_0;
            w = (int) zz_2;
            zz[2] = (w << 1) | c;
            c = w >>> 31;
            zz_3 += (zz_2 >>> 32) + x_2 * x_1;
            zz_4 += zz_3 >>> 32;
            zz_3 &= M;
        }

        long x_3 = x[3] & M;
        long zz_5 = (zz[5] & M) + (zz_4 >>> 32);
        zz_4 &= M;
        long zz_6 = (zz[6] & M) + (zz_5 >>> 32);
        zz_5 &= M;
        {
            zz_3 += x_3 * x_0;
            w = (int) zz_3;
            zz[3] = (w << 1) | c;
            c = w >>> 31;
            zz_4 += (zz_3 >>> 32) + x_3 * x_1;
            zz_5 += (zz_4 >>> 32) + x_3 * x_2;
            zz_4 &= M;
            zz_6 += zz_5 >>> 32;
            zz_5 &= M;
        }

        long x_4 = x[4] & M;
        long zz_7 = (zz[7] & M) + (zz_6 >>> 32);
        zz_6 &= M;
        long zz_8 = (zz[8] & M) + (zz_7 >>> 32);
        zz_7 &= M;
        {
            zz_4 += x_4 * x_0;
            w = (int) zz_4;
            zz[4] = (w << 1) | c;
            c = w >>> 31;
            zz_5 += (zz_4 >>> 32) + x_4 * x_1;
            zz_6 += (zz_5 >>> 32) + x_4 * x_2;
            zz_5 &= M;
            zz_7 += (zz_6 >>> 32) + x_4 * x_3;
            zz_6 &= M;
            zz_8 += zz_7 >>> 32;
            zz_7 &= M;
        }

        long x_5 = x[5] & M;
        long zz_9 = (zz[9] & M) + (zz_8 >>> 32);
        zz_8 &= M;
        long zz_10 = (zz[10] & M) + (zz_9 >>> 32);
        zz_9 &= M;
        {
            zz_5 += x_5 * x_0;
            w = (int) zz_5;
            zz[5] = (w << 1) | c;
            c = w >>> 31;
            zz_6 += (zz_5 >>> 32) + x_5 * x_1;
            zz_7 += (zz_6 >>> 32) + x_5 * x_2;
            zz_6 &= M;
            zz_8 += (zz_7 >>> 32) + x_5 * x_3;
            zz_7 &= M;
            zz_9 += (zz_8 >>> 32) + x_5 * x_4;
            zz_8 &= M;
            zz_10 += zz_9 >>> 32;
            zz_9 &= M;
        }

        long x_6 = x[6] & M;
        long zz_11 = (zz[11] & M) + (zz_10 >>> 32);
        zz_10 &= M;
        long zz_12 = (zz[12] & M) + (zz_11 >>> 32);
        zz_11 &= M;
        {
            zz_6 += x_6 * x_0;
            w = (int) zz_6;
            zz[6] = (w << 1) | c;
            c = w >>> 31;
            zz_7 += (zz_6 >>> 32) + x_6 * x_1;
            zz_8 += (zz_7 >>> 32) + x_6 * x_2;
            zz_7 &= M;
            zz_9 += (zz_8 >>> 32) + x_6 * x_3;
            zz_8 &= M;
            zz_10 += (zz_9 >>> 32) + x_6 * x_4;
            zz_9 &= M;
            zz_11 += (zz_10 >>> 32) + x_6 * x_5;
            zz_10 &= M;
            zz_12 += zz_11 >>> 32;
            zz_11 &= M;
        }

        long x_7 = x[7] & M;
        long zz_13 = (zz[13] & M) + (zz_12 >>> 32);
        zz_12 &= M;
        long zz_14 = (zz[14] & M) + (zz_13 >>> 32);
        zz_13 &= M;
        {
            zz_7 += x_7 * x_0;
            w = (int) zz_7;
            zz[7] = (w << 1) | c;
            c = w >>> 31;
            zz_8 += (zz_7 >>> 32) + x_7 * x_1;
            zz_9 += (zz_8 >>> 32) + x_7 * x_2;
            zz_10 += (zz_9 >>> 32) + x_7 * x_3;
            zz_11 += (zz_10 >>> 32) + x_7 * x_4;
            zz_12 += (zz_11 >>> 32) + x_7 * x_5;
            zz_13 += (zz_12 >>> 32) + x_7 * x_6;
            zz_14 += zz_13 >>> 32;
        }

        w = (int) zz_8;
        zz[8] = (w << 1) | c;
        c = w >>> 31;
        w = (int) zz_9;
        zz[9] = (w << 1) | c;
        c = w >>> 31;
        w = (int) zz_10;
        zz[10] = (w << 1) | c;
        c = w >>> 31;
        w = (int) zz_11;
        zz[11] = (w << 1) | c;
        c = w >>> 31;
        w = (int) zz_12;
        zz[12] = (w << 1) | c;
        c = w >>> 31;
        w = (int) zz_13;
        zz[13] = (w << 1) | c;
        c = w >>> 31;
        w = (int) zz_14;
        zz[14] = (w << 1) | c;
        c = w >>> 31;
        w = zz[15] + (int) (zz_14 >>> 32);
        zz[15] = (w << 1) | c;
    }

    public static int subtract(int[] x, int[] y, int[] z) {
        long c = 0;
        for (int i = 0; i < 8; i++) {
            c += (x[i] & M) - (y[i] & M);
            z[i] = (int) c;
            c >>= 32;
        }
        return (int) c;
    }

    public static BigInteger toBigInteger(int[] x) {
        byte[] bs = new byte[32];
        for (int i = 0; i < 8; ++i) {
            int x_i = x[i];
            if (x_i != 0) {
                Util.intToBigEndian(x_i, bs, (7 - i) << 2);
            }
        }
        return new BigInteger(1, bs);
    }
}
