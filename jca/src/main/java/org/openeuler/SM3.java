/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
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

import org.openeuler.util.Util;
import java.security.MessageDigestSpi;
import java.util.Arrays;

public class SM3 extends MessageDigestSpi implements Cloneable{
    private static final int DIGEST_LENGTH = 32;   // Byte length of the final result (256 bits, 32 bytes)
    private static final int BLOCK_BYTE_SIZE = 512 / 8; // Byte length of the message block, (512 bits, 64 bytes, 16 words)
    private long byteCount;

    private final byte[]  byteBuf = new byte[BLOCK_BYTE_SIZE];  // Message block buffer
    private int byteBufOff;

    private final int[] V = new int[8]; // 8 words
    private final int[] W = new int[68];

    /*
    * Calculate the Tj value in advance for the compression function
    *
    * Tj = 79cc4519        when 0  < = j < = 15
    * Tj = 7a879d8a        when 16 < = j < = 63
    * Tj = (Tj <<< (j mod 32))
    */
    private static final int[] T = new int[64];
    static
    {
        for (int i = 0; i < 16; ++i)
        {
            // T[i] = 0x79CC4519 <<< i
            T[i] = Util.rotateShiftLeft(0x79CC4519, i);
        }
        for (int i = 16; i < 64; ++i)
        {
            // T[i] = 0x7A879D8A <<< (i mod 32)
            T[i] = Util.rotateShiftLeft(0x7A879D8A, i % 32);
        }
    }


    /**
    * Standard constructor
    */
    public SM3()
    {
        engineReset();
    }

    /**
    * Copy constructor.  This will copy the state of the provided
    * message digest.
    */
    public SM3(SM3 t)
    {
        System.arraycopy(t.V, 0, this.V, 0, this.V.length);
        System.arraycopy(t.byteBuf, 0, this.byteBuf, 0, this.byteBuf.length);
        this.byteCount = t.byteCount;
        this.byteBufOff = t.byteBufOff;
    }

    @Override
    protected void engineUpdate(byte input) {
        byteBuf[byteBufOff++] = input;

        if (byteBufOff == byteBuf.length)
        {
            ME(); // Message extension
            CF(); // Compression Function
        }
        byteCount++;
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        len = Math.max(0,  len);

        // fill the current message group
        int i = 0;
        if (byteBufOff != 0)
        {
            while (i < len)
            {
                byteBuf[byteBufOff++] = input[offset + i++];
                if (byteBufOff == byteBuf.length)
                {
                    ME(); // Message extension
                    CF(); // Compression Function
                    break;
                }
            }
        }

        // process whole message block.
        int limit = ((len - i) & ~63) + i;
        for (; i < limit; i += 64)
        {
            System.arraycopy(input, offset + i, this.byteBuf, 0, 64);
            ME(); // Message extension
            CF(); // Compression Function
        }

        // load in the remainder.
        while (i < len)
        {
            byteBuf[byteBufOff++] = input[offset + i++];
        }

        byteCount += len;
    }

    @Override
    protected byte[] engineDigest() {
        long bitLength = (byteCount << 3);

        // Add the bit "1" to the end of the message.
        engineUpdate((byte)128);

        padding(bitLength); // Padding the message
        ME(); // Message extension
        CF(); // Compression Function

        byte[]  digestBytes = new byte[engineGetDigestLength()];
        Util.intToBigEndian(V, digestBytes, 0);

        engineReset();

        return digestBytes;
    }

    @Override
    protected void engineReset() {
         for (int i = 0; i < byteBuf.length; i++)
         {
             this.byteBuf[i] = 0;
         }

         this.V[0] = 0x7380166F;
         this.V[1] = 0x4914B2B9;
         this.V[2] = 0x172442D7;
         this.V[3] = 0xDA8A0600;
         this.V[4] = 0xA96F30BC;
         this.V[5] = 0x163138AA;
         this.V[6] = 0xE38DEE4D;
         this.V[7] = 0xB0FB0E4E;

         this.byteCount = 0;
         this.byteBufOff = 0;
     }

    public int engineGetDigestLength()
     {
         return DIGEST_LENGTH;
     }

    /**
     * Permutation function
     * @param x input number
     * @return P0(X) = X XOR (X <<<  9) XOR (X <<< 17)
     */
    private int P0(final int x)
    {
        // P0(x) = (x ^ (x <<< 9) ^ (x <<< 17);
        return (x ^ Util.rotateShiftLeft(x, 9) ^ Util.rotateShiftLeft(x, 17));
    }

    /**
     * Permutation function
     * @param x input number
     * @return P1(X) = X XOR (X <<< 15) XOR (X <<< 23)
     */
    private int P1(final int x)
    {
        // P1(x) = (x ^ (x <<< 15) ^ (x <<< 23);
        return (x ^ Util.rotateShiftLeft(x, 15) ^ Util.rotateShiftLeft(x, 23));
    }

    /**
     * Boolean function
     * FFj(X;Y;Z) = X XOR Y XOR Z                       when 0  < = j < = 15
     *            = (X AND Y) OR (X AND Z) OR (Y AND Z) when 16 < = j < = 63
     * @param j function index
     * @param x X
     * @param y Y
     * @param z X
     * @return FFj(x, y, z)
     */
    private int FF(final int j, final int x, final int y, final int z) {
        if (j <= 15) {
            return (x ^ y ^ z);
        } else {
            return ((x & y) | (x & z) | (y & z));
        }
    }

    /*
    * Boolean function
    * GGj(X;Y;Z) = X XOR Y XOR Z                       when 0  < = j < = 15
    *            = (X AND Y) OR (NOT X AND Z)          when 16 < = j < = 63
    * */

    /**
     * Boolean function
     * GGj(X;Y;Z) = X XOR Y XOR Z                       when 0  < = j < = 15
     *            = (X AND Y) OR (NOT X AND Z)          when 16 < = j < = 63
     * @param j function index
     * @param x X
     * @param y Y
     * @param z Z
     * @return GGj(x, y, z)
     */
    private int GG(final int j,final int x, final int y, final int z) {
        if (j <= 15) {
            return (x ^ y ^ z);
        } else {
            return ((x & y) | ((~x) & z));
        }
    }

    /**
     * Message Extension
     * W[j] = B[i]                                                                         when 0  < = j < = 15
     * W[j] = P1(W[j-16] XOR W[j-9] XOR (W[j-3] <<< 15)) XOR (W[j-13] <<< 7) XOR W[j-6]    when 16 < = j < = 63
     *
     * HINT:
     *     In order to optimize data storage, W' in the message extension will be
     *     directly calculated when it is used in the compression function.
     */
    protected void ME() {
        for (int j = 0; j < 16; ++j) {
            // Form bytes into words by BigEndian
            int index = j << 2;
            this.W[j] = (((this.byteBuf[index] & 0xff) << 24) |
                    ((this.byteBuf[++index] & 0xff) << 16) |
                    ((this.byteBuf[++index] & 0xff) << 8) |
                    ((this.byteBuf[++index] & 0xff)));
        }
        for (int j = 16; j < 68; ++j) {
            // W[j] = P1(W[j-16] XOR W[j-9] XOR (W[j-3] <<< 15)) XOR (W[j-13] <<< 7) XOR W[j-6]
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ Util.rotateShiftLeft(W[j - 3], 15)) ^ Util.rotateShiftLeft(W[j - 13], 7) ^ W[j - 6];
        }
    }

    /**
     * Compression Function
     */
    protected void CF()
    {
        int A = this.V[0];
        int B = this.V[1];
        int C = this.V[2];
        int D = this.V[3];
        int E = this.V[4];
        int F = this.V[5];
        int G = this.V[6];
        int H = this.V[7];


        for (int j = 0; j < 64; ++j)
        {
            int A_r12 = Util.rotateShiftLeft(A, 12); // A_r12 = A <<< 12
            // SS1 = ((A <<< 12) + E + (T[j] <<< (j mod 32))) <<< 7, T[j] has been processed in advance.
            int SS1 = Util.rotateShiftLeft(A_r12 + E + T[j], 7);
            int SS2 = SS1 ^ A_r12;
            int TT1 = FF(j, A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
            int TT2 = GG(j, E, F, G) + H + SS1 + W[j];
            D = C;
            C = Util.rotateShiftLeft(B, 9); // C = B <<< 9
            B = A;
            A = TT1;
            H = G;
            G = Util.rotateShiftLeft(F, 19); // G = F <<< 19
            F = E;
            E = P0(TT2);
        }

        this.V[0] ^= A;
        this.V[1] ^= B;
        this.V[2] ^= C;
        this.V[3] ^= D;
        this.V[4] ^= E;
        this.V[5] ^= F;
        this.V[6] ^= G;
        this.V[7] ^= H;

        this.byteBufOff = 0;
    }

    /**
     * Padding
     * @param bitLength bit length of message length
     */
    protected void padding(long bitLength)
    {
        if (this.byteBufOff > (BLOCK_BYTE_SIZE - 8))
        {
            Arrays.fill(byteBuf, byteBufOff, BLOCK_BYTE_SIZE, (byte)0); // fill with zero
            byteBufOff = BLOCK_BYTE_SIZE;
            ME(); // Message extension
            CF(); // Compression Function
        }
        // Fill with zero words, until reach 2nd to last slot
        if (this.byteBufOff < (BLOCK_BYTE_SIZE - 8))
        {
            Arrays.fill(byteBuf, byteBufOff, BLOCK_BYTE_SIZE - 8, (byte)0);
            this.byteBufOff = BLOCK_BYTE_SIZE - 8;
        }

        // Store input data length in BITS
        for (int i = 64 - 8; i >= 0; i -= 8) {
            this.byteBuf[this.byteBufOff++] = (byte)(bitLength >>> i);
        }
    }

    /**
     * Clone
     * @return SM3 class
     * @throws CloneNotSupportedException
     */
    public Object clone() throws CloneNotSupportedException {
        super.clone();
        return new SM3(this);
    }
}