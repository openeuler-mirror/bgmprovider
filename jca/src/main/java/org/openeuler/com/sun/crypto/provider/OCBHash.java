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

package org.openeuler.com.sun.crypto.provider;

import java.util.Arrays;
import java.util.List;

public class OCBHash {
    // L_*
    private byte[] l_sterisk;
    // L_i
    private List<byte[]> l;
    // Sum (Hash result)
    private byte[] sumBlock;
    // Offset
    private byte[] offsetBlock;
    // AAD block
    private byte[] aadBlock;
    // AAD block position
    private int aadBlockPos;
    // AAD block count
    private int aadBlockCount;
    private SymmetricCipher embeddedCipher;
    private int blockSize;

    // additional variables for save/restore calls
    private byte[] sumBlockSave;
    private byte[] offsetBlockSave;
    private byte[] aadBlockSave;
    private int aadBlockPosSave;
    private int aadBlockCountSave;


    OCBHash(SymmetricCipher embeddedCipher) {
        this.embeddedCipher = embeddedCipher;
    }

    void init(byte[] l_sterisk, List<byte[]> l) {
        this.l_sterisk = l_sterisk;
        this.l = l;
        this.blockSize = embeddedCipher.getBlockSize();

        // Sum, Offset
        this.sumBlock = new byte[blockSize];
        this.offsetBlock = new byte[blockSize];

        // AAD block, bock position, block count
        this.aadBlock = new byte[blockSize];
        this.aadBlockPos = 0;
        this.aadBlockCount = 0;
    }

    /**
     * Process any whole blocks
     * Sum_0 = zeros(128)
     * Offset_0 = zeros(128)
     * for each 1 <= i <= m
     *     Offset_i = Offset_{i-1} xor L_{ntz(i)}
     *     Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)
     * end for
     *
     * @param src
     * @param offset
     * @param len
     */
    void update(byte[] src, int offset, int len) {
        for (int i = 0; i < len; i++) {
            aadBlock[aadBlockPos++] = src[offset + i];
            if (aadBlockPos == aadBlock.length) {
                processHash();
            }
        }
    }

    /**
     * Process any final partial block; compute final hash value
     * if bitlen(A_*) > 0 then
     *     Offset_* = Offset_m xor L_*
     *     CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_*
     *     Sum = Sum_m xor ENCIPHER(K, CipherInput)
     * else
     *     Sum = Sum_m
     * end if
     *
     * @return
     */
    byte[] digest() {
        if (aadBlockPos == 0) {
            return sumBlock;
        }
        ocb_extend(aadBlock, aadBlockPos);
        updateHash(l_sterisk);
        return sumBlock;
    }

    void save() {
        sumBlockSave = Arrays.copyOf(sumBlock, sumBlock.length);
        offsetBlockSave = Arrays.copyOf(offsetBlock, offsetBlock.length);
        aadBlockSave = Arrays.copyOf(aadBlock, aadBlock.length);
        aadBlockPosSave = aadBlockPos;
        aadBlockCountSave = aadBlockCount;
    }

    void restore() {
        System.arraycopy(sumBlockSave, 0, sumBlock, 0, sumBlock.length);
        System.arraycopy(offsetBlockSave, 0, offsetBlock, 0, offsetBlock.length);
        System.arraycopy(aadBlockSave, 0, aadBlock, 0, aadBlock.length);
        aadBlockPos = aadBlockPosSave;
        aadBlockCount = aadBlockCountSave;
    }

    void reset() {
        // Sum, Offset
        Arrays.fill(this.sumBlock, (byte) 0);
        Arrays.fill(this.offsetBlock, (byte) 0);

        // AAD block, bock position, block count
        Arrays.fill(this.aadBlock, (byte) 0);
        this.aadBlockPos = 0;
        this.aadBlockCount = 0;
    }

    /**
     * Offset_i = Offset_{i-1} xor L_{ntz(i)}
     * Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)
     */
    private void processHash() {
        ++aadBlockCount;
        byte[] lSub = getLSub(l, ocb_ntz(aadBlockCount));
        updateHash(lSub);
        aadBlockPos = 0;
    }

    private void updateHash(byte[] lSub) {
        xor(offsetBlock, lSub);
        xor(aadBlock, offsetBlock);
        embeddedCipher.encryptBlock(aadBlock, 0, aadBlock, 0);
        xor(sumBlock, aadBlock);
    }

    static byte[] getLSub(List<byte[]> list, int index) {
        int limit = list.size() - 1;
        while (index > limit) {
            byte[] l_size = ocb_double(list.get(limit));
            list.add(l_size);
            limit++;
        }
        return list.get(index);
    }

    /**
     * The number of trailing zero bits in the base-2
     * representation of the positive integer n.  More
     * formally, ntz(n) is the largest integer x for which 2^x
     * divides n.
     * @param n
     * @return the largest integer x for which 2^x divides n
     */
    static int ocb_ntz(int n) {
        return Integer.numberOfTrailingZeros(n);
    }

    /**
     * If S[1] == 0, then double(S) == (S[2..128] || 0);
     *  otherwise, double(S) == (S[2..128] || 0) xor
     * (zeros(120) || 10000111).
     * @param block
     * @return
     */
    static byte[] ocb_double(byte[] block) {
        byte[] result = new byte[block.length];
        int bit = 0;
        for (int i = block.length - 1; i >= 0; i--) {
            int b = block[i] & 0xff;
            result[i] = (byte) ((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
        result[result.length - 1] ^= (byte) (0x87 >>> ((1 - bit) << 3));
        return result;
    }

    static void xor(byte[] block, byte[] values) {
        // len is always equal 16
        int len = Math.min(block.length, values.length);
        for (int i = 0; i < len; i++) {
            block[i] ^= values[i];
        }
    }

    static void ocb_extend(byte[] block, int pos) {
        block[pos] = (byte) 0x80;
        while (++pos < block.length) {
            block[pos] = 0;
        }
    }
}
