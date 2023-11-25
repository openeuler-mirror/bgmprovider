package org.openeuler.util;

/*
 * The implementation of this class comes from
 * https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/math/raw/Mod.java
 * Modular inversion as implemented in this class is based on the paper "Fast constant-time gcd
 * computation and modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
 */

public class Mod {
    private static final int M30 = 0x3FFFFFFF;
    private static final long M32L = 0xFFFFFFFFL;

    public static void checkedModOddInverse(int[] m, int[] x, int[] z) {
        if (0 == modOddInverse(m, x, z)) {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static int inverse32(int d) {
        int x = d;                          // d.x == 1 mod 2**3
        x *= 2 - d * x;                     // d.x == 1 mod 2**6
        x *= 2 - d * x;                     // d.x == 1 mod 2**12
        x *= 2 - d * x;                     // d.x == 1 mod 2**24
        x *= 2 - d * x;                     // d.x == 1 mod 2**48
        return x;
    }

    public static int modOddInverse(int[] m, int[] x, int[] z) {
        int len32 = m.length;

        int bits = (len32 << 5) - Integer.numberOfLeadingZeros(m[len32 - 1]);
        int len30 = (bits + 29) / 30;

        int[] t = new int[4];
        int[] D = new int[len30];
        int[] E = new int[len30];
        int[] F = new int[len30];
        int[] G = new int[len30];
        int[] M = new int[len30];

        E[0] = 1;
        encode30(bits, x, 0, G, 0);
        encode30(bits, m, 0, M, 0);
        System.arraycopy(M, 0, F, 0, len30);

        int delta = 0;
        int m0Inv32 = inverse32(M[0]);
        int maxDivsteps = getMaximumDivsteps(bits);

        for (int divSteps = 0; divSteps < maxDivsteps; divSteps += 30) {
            delta = divsteps30(delta, F[0], G[0], t);
            updateDE30(len30, D, E, t, m0Inv32, M);
            updateFG30(len30, F, G, t);
        }

        int signF = F[len30 - 1] >> 31;
        cnegate30(len30, signF, F);

        /*
         * D is in the range (-2.M, M). First, conditionally add M if D is negative, to bring it
         * into the range (-M, M). Then normalize by conditionally negating (according to signF)
         * and/or then adding M, to bring it into the range [0, M).
         */
        cnormalize30(len30, signF, D, M);

        decode30(bits, D, 0, z, 0);

        return Nat.equalTo(len30, F, 1) & Nat.equalToZero(len30, G);
    }


    private static void cnegate30(int len30, int cond, int[] D) {
        int c = 0, last = len30 - 1;
        for (int i = 0; i < last; ++i) {
            c += (D[i] ^ cond) - cond;
            D[i] = c & M30;
            c >>= 30;
        }
        c += (D[last] ^ cond) - cond;
        D[last] = c;
    }

    private static void cnormalize30(int len30, int condNegate, int[] D, int[] M) {
        int last = len30 - 1;

        {
            int c = 0, condAdd = D[last] >> 31;
            for (int i = 0; i < last; ++i) {
                int di = D[i] + (M[i] & condAdd);
                di = (di ^ condNegate) - condNegate;
                c += di;
                D[i] = c & M30;
                c >>= 30;
            }
            {
                int di = D[last] + (M[last] & condAdd);
                di = (di ^ condNegate) - condNegate;
                c += di;
                D[last] = c;
            }
        }

        {
            int c = 0, condAdd = D[last] >> 31;
            for (int i = 0; i < last; ++i) {
                int di = D[i] + (M[i] & condAdd);
                c += di;
                D[i] = c & M30;
                c >>= 30;
            }
            {
                int di = D[last] + (M[last] & condAdd);
                c += di;
                D[last] = c;
            }
        }
    }

    private static void decode30(int bits, int[] x, int xOff, int[] z, int zOff) {
        int avail = 0;
        long data = 0L;

        while (bits > 0) {
            while (avail < Math.min(32, bits)) {
                data |= (long) x[xOff++] << avail;
                avail += 30;
            }

            z[zOff++] = (int) data;
            data >>>= 32;
            avail -= 32;
            bits -= 32;
        }
    }

    private static int divsteps30(int delta, int f0, int g0, int[] t) {
        int u = 1 << 30, v = 0, q = 0, r = 1 << 30;
        int f = f0, g = g0;

        for (int i = 0; i < 30; ++i) {
            int c1 = delta >> 31;
            int c2 = -(g & 1);

            int x = f ^ c1;
            int y = u ^ c1;
            int z = v ^ c1;

            g -= x & c2;
            q -= y & c2;
            r -= z & c2;

            c2 &= ~c1;
            delta = (delta ^ c2) - (c2 - 1);

            f += g & c2;
            u += q & c2;
            v += r & c2;

            g >>= 1;
            q >>= 1;
            r >>= 1;
        }

        t[0] = u;
        t[1] = v;
        t[2] = q;
        t[3] = r;

        return delta;
    }

    private static void encode30(int bits, int[] x, int xOff, int[] z, int zOff) {
        int avail = 0;
        long data = 0L;

        while (bits > 0) {
            if (avail < Math.min(30, bits)) {
                data |= (x[xOff++] & M32L) << avail;
                avail += 32;
            }

            z[zOff++] = (int) data & M30;
            data >>>= 30;
            avail -= 30;
            bits -= 30;
        }
    }

    private static int getMaximumDivsteps(int bits) {
        return (49 * bits + (bits < 46 ? 80 : 47)) / 17;
    }

    private static void updateDE30(int len30, int[] D, int[] E, int[] t, int m0Inv32, int[] M) {
        final int u = t[0], v = t[1], q = t[2], r = t[3];
        int di, ei, i, md, me, mi, sd, se;
        long cd, ce;

        /*
         * We accept D (E) in the range (-2.M, M) and conceptually add the modulus to the input
         * value if it is initially negative. Instead of adding it explicitly, we add u and/or v (q
         * and/or r) to md (me).
         */
        sd = D[len30 - 1] >> 31;
        se = E[len30 - 1] >> 31;

        md = (u & sd) + (v & se);
        me = (q & sd) + (r & se);

        mi = M[0];
        di = D[0];
        ei = E[0];

        cd = (long) u * di + (long) v * ei;
        ce = (long) q * di + (long) r * ei;

        /*
         * Subtract from md/me an extra term in the range [0, 2^30) such that the low 30 bits of the
         * intermediate D/E values will be 0, allowing clean division by 2^30. The final D/E are
         * thus in the range (-2.M, M), consistent with the input constraint.
         */
        md -= (m0Inv32 * (int) cd + md) & M30;
        me -= (m0Inv32 * (int) ce + me) & M30;

        cd += (long) mi * md;
        ce += (long) mi * me;

        cd >>= 30;
        ce >>= 30;

        for (i = 1; i < len30; ++i) {
            mi = M[i];
            di = D[i];
            ei = E[i];

            cd += (long) u * di + (long) v * ei + (long) mi * md;
            ce += (long) q * di + (long) r * ei + (long) mi * me;

            D[i - 1] = (int) cd & M30;
            cd >>= 30;
            E[i - 1] = (int) ce & M30;
            ce >>= 30;
        }

        D[len30 - 1] = (int) cd;
        E[len30 - 1] = (int) ce;
    }

    private static void updateFG30(int len30, int[] F, int[] G, int[] t) {
        final int u = t[0], v = t[1], q = t[2], r = t[3];
        int fi, gi, i;
        long cf, cg;

        fi = F[0];
        gi = G[0];

        cf = (long) u * fi + (long) v * gi;
        cg = (long) q * fi + (long) r * gi;

        cf >>= 30;
        cg >>= 30;

        for (i = 1; i < len30; ++i) {
            fi = F[i];
            gi = G[i];

            cf += (long) u * fi + (long) v * gi;
            cg += (long) q * fi + (long) r * gi;

            F[i - 1] = (int) cf & M30;
            cf >>= 30;
            G[i - 1] = (int) cg & M30;
            cg >>= 30;
        }

        F[len30 - 1] = (int) cf;
        G[len30 - 1] = (int) cg;
    }
}
