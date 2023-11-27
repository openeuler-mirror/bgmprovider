package org.openeuler.util;

/**
 * The implementation of this class comes from
 * https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/math/ec/custom/gm/SM2P256V1Field.java
 */
public class SM2P256CurveUtil {
    private static final long M = 0xFFFFFFFFL;

    // 2^256 - 2^224 - 2^96 + 2^64 - 1
    static final int[] P = new int[]{0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFE};
    private static final int[] PExt = new int[]{00000001, 0x00000000, 0xFFFFFFFE, 0x00000001, 0x00000001, 0xFFFFFFFE,
            0x00000000, 0x00000002, 0xFFFFFFFE, 0xFFFFFFFD, 0x00000003, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
            0xFFFFFFFE};
    private static final int P7s1 = 0xFFFFFFFE >>> 1;
    private static final int PExt15s1 = 0xFFFFFFFE >>> 1;

    public static void add(int[] x, int[] y, int[] z) {
        int c = Nat256.add(x, y, z);
        if (c != 0 || ((z[7] >>> 1) >= P7s1 && Nat256.gte(z, P))) {
            addPInvTo(z);
        }
    }

    public static void inv(int[] x, int[] z) {
        Mod.checkedModOddInverse(P, x, z);
    }

    public static int isZero(int[] x) {
        int d = 0;
        for (int i = 0; i < 8; ++i) {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z) {
        int[] tt = Nat256.createExt();
        Nat256.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz) {
        int c = Nat256.mulAddTo(x, y, zz);
        if (c != 0 || ((zz[15] >>> 1) >= PExt15s1 && Nat.gte(16, zz, PExt))) {
            Nat.subFrom(16, PExt, zz);
        }
    }

    public static void negate(int[] x, int[] z) {
        if (0 != isZero(x)) {
            Nat256.subtract(P, P, z);
        } else {
            Nat256.subtract(P, x, z);
        }
    }

    public static void reduce(int[] xx, int[] z) {
        long xx08 = xx[8] & M, xx09 = xx[9] & M, xx10 = xx[10] & M, xx11 = xx[11] & M;
        long xx12 = xx[12] & M, xx13 = xx[13] & M, xx14 = xx[14] & M, xx15 = xx[15] & M;

        long t0 = xx08 + xx09;
        long t1 = xx10 + xx11;
        long t2 = xx12 + xx15;
        long t3 = xx13 + xx14;
        long t4 = t3 + (xx15 << 1);

        long ts = t0 + t3;
        long tt = t1 + t2 + ts;

        long cc = 0;
        cc += (xx[0] & M) + tt + xx13 + xx14 + xx15;
        z[0] = (int) cc;
        cc >>= 32;
        cc += (xx[1] & M) + tt - xx08 + xx14 + xx15;
        z[1] = (int) cc;
        cc >>= 32;
        cc += (xx[2] & M) - ts;
        z[2] = (int) cc;
        cc >>= 32;
        cc += (xx[3] & M) + tt - xx09 - xx10 + xx13;
        z[3] = (int) cc;
        cc >>= 32;
        cc += (xx[4] & M) + tt - t1 - xx08 + xx14;
        z[4] = (int) cc;
        cc >>= 32;
        cc += (xx[5] & M) + t4 + xx10;
        z[5] = (int) cc;
        cc >>= 32;
        cc += (xx[6] & M) + xx11 + xx14 + xx15;
        z[6] = (int) cc;
        cc >>= 32;
        cc += (xx[7] & M) + tt + t4 + xx12;
        z[7] = (int) cc;
        cc >>= 32;

        reduce32((int) cc, z);
    }

    public static void reduce32(int x, int[] z) {
        long cc = 0;
        if (x != 0) {
            long xx08 = x & M;

            cc += (z[0] & M) + xx08;
            z[0] = (int) cc;
            cc >>= 32;
            if (cc != 0) {
                cc += (z[1] & M);
                z[1] = (int) cc;
                cc >>= 32;
            }
            cc += (z[2] & M) - xx08;
            z[2] = (int) cc;
            cc >>= 32;
            cc += (z[3] & M) + xx08;
            z[3] = (int) cc;
            cc >>= 32;
            if (cc != 0) {
                cc += (z[4] & M);
                z[4] = (int) cc;
                cc >>= 32;
                cc += (z[5] & M);
                z[5] = (int) cc;
                cc >>= 32;
                cc += (z[6] & M);
                z[6] = (int) cc;
                cc >>= 32;
            }
            cc += (z[7] & M) + xx08;
            z[7] = (int) cc;
            cc >>= 32;
        }

        if (cc != 0 || ((z[7] >>> 1) >= P7s1 && Nat256.gte(z, P))) {
            addPInvTo(z);
        }
    }

    public static void square(int[] x, int[] z) {
        int[] tt = Nat256.createExt();
        Nat256.square(x, tt);
        reduce(tt, z);
    }

    public static void subtract(int[] x, int[] y, int[] z) {
        int c = Nat256.subtract(x, y, z);
        if (c != 0) {
            subPInvFrom(z);
        }
    }

    public static void twice(int[] x, int[] z) {
        int c = Nat.shiftUpBit(8, x, 0, z);
        if (c != 0 || ((z[7] >>> 1) >= P7s1 && Nat256.gte(z, P))) {
            addPInvTo(z);
        }
    }

    private static void addPInvTo(int[] z) {
        long c = (z[0] & M) + 1;
        z[0] = (int) c;
        c >>= 32;
        if (c != 0) {
            c += (z[1] & M);
            z[1] = (int) c;
            c >>= 32;
        }
        c += (z[2] & M) - 1;
        z[2] = (int) c;
        c >>= 32;
        c += (z[3] & M) + 1;
        z[3] = (int) c;
        c >>= 32;
        if (c != 0) {
            c += (z[4] & M);
            z[4] = (int) c;
            c >>= 32;
            c += (z[5] & M);
            z[5] = (int) c;
            c >>= 32;
            c += (z[6] & M);
            z[6] = (int) c;
            c >>= 32;
        }
        c += (z[7] & M) + 1;
        z[7] = (int) c;
    }

    private static void subPInvFrom(int[] z) {
        long c = (z[0] & M) - 1;
        z[0] = (int) c;
        c >>= 32;
        if (c != 0) {
            c += (z[1] & M);
            z[1] = (int) c;
            c >>= 32;
        }
        c += (z[2] & M) + 1;
        z[2] = (int) c;
        c >>= 32;
        c += (z[3] & M) - 1;
        z[3] = (int) c;
        c >>= 32;
        if (c != 0) {
            c += (z[4] & M);
            z[4] = (int) c;
            c >>= 32;
            c += (z[5] & M);
            z[5] = (int) c;
            c >>= 32;
            c += (z[6] & M);
            z[6] = (int) c;
            c >>= 32;
        }
        c += (z[7] & M) - 1;
        z[7] = (int) c;
    }
}
