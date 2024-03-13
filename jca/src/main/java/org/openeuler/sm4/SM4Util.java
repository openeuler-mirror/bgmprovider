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

package org.openeuler.sm4;

import org.openeuler.util.Util;

/**
 * implement SM4  encryption and decryption
 */
public class SM4Util {

    private static final byte[] S_BOX = new byte[]{
            (byte) 0xD6, (byte) 0x90, (byte) 0xE9, (byte) 0xFE, (byte) 0xCC, (byte) 0xE1, (byte) 0x3D, (byte) 0xB7, 
            (byte) 0x16, (byte) 0xB6, (byte) 0x14, (byte) 0xC2, (byte) 0x28, (byte) 0xFB, (byte) 0x2C, (byte) 0x05,
            (byte) 0x2B, (byte) 0x67, (byte) 0x9A, (byte) 0x76, (byte) 0x2A, (byte) 0xBE, (byte) 0x04, (byte) 0xC3, 
            (byte) 0xAA, (byte) 0x44, (byte) 0x13, (byte) 0x26, (byte) 0x49, (byte) 0x86, (byte) 0x06, (byte) 0x99,
            (byte) 0x9C, (byte) 0x42, (byte) 0x50, (byte) 0xF4, (byte) 0x91, (byte) 0xEF, (byte) 0x98, (byte) 0x7A, 
            (byte) 0x33, (byte) 0x54, (byte) 0x0B, (byte) 0x43, (byte) 0xED, (byte) 0xCF, (byte) 0xAC, (byte) 0x62,
            (byte) 0xE4, (byte) 0xB3, (byte) 0x1C, (byte) 0xA9, (byte) 0xC9, (byte) 0x08, (byte) 0xE8, (byte) 0x95, 
            (byte) 0x80, (byte) 0xDF, (byte) 0x94, (byte) 0xFA, (byte) 0x75, (byte) 0x8F, (byte) 0x3F, (byte) 0xA6,
            (byte) 0x47, (byte) 0x07, (byte) 0xA7, (byte) 0xFC, (byte) 0xF3, (byte) 0x73, (byte) 0x17, (byte) 0xBA, 
            (byte) 0x83, (byte) 0x59, (byte) 0x3C, (byte) 0x19, (byte) 0xE6, (byte) 0x85, (byte) 0x4F, (byte) 0xA8,
            (byte) 0x68, (byte) 0x6B, (byte) 0x81, (byte) 0xB2, (byte) 0x71, (byte) 0x64, (byte) 0xDA, (byte) 0x8B, 
            (byte) 0xF8, (byte) 0xEB, (byte) 0x0F, (byte) 0x4B, (byte) 0x70, (byte) 0x56, (byte) 0x9D, (byte) 0x35,
            (byte) 0x1E, (byte) 0x24, (byte) 0x0E, (byte) 0x5E, (byte) 0x63, (byte) 0x58, (byte) 0xD1, (byte) 0xA2, 
            (byte) 0x25, (byte) 0x22, (byte) 0x7C, (byte) 0x3B, (byte) 0x01, (byte) 0x21, (byte) 0x78, (byte) 0x87,
            (byte) 0xD4, (byte) 0x00, (byte) 0x46, (byte) 0x57, (byte) 0x9F, (byte) 0xD3, (byte) 0x27, (byte) 0x52,
            (byte) 0x4C, (byte) 0x36, (byte) 0x02, (byte) 0xE7, (byte) 0xA0, (byte) 0xC4, (byte) 0xC8, (byte) 0x9E,
            (byte) 0xEA, (byte) 0xBF, (byte) 0x8A, (byte) 0xD2, (byte) 0x40, (byte) 0xC7, (byte) 0x38, (byte) 0xB5,
            (byte) 0xA3, (byte) 0xF7, (byte) 0xF2, (byte) 0xCE, (byte) 0xF9, (byte) 0x61, (byte) 0x15, (byte) 0xA1,
            (byte) 0xE0, (byte) 0xAE, (byte) 0x5D, (byte) 0xA4, (byte) 0x9B, (byte) 0x34, (byte) 0x1A, (byte) 0x55,
            (byte) 0xAD, (byte) 0x93, (byte) 0x32, (byte) 0x30, (byte) 0xF5, (byte) 0x8C, (byte) 0xB1, (byte) 0xE3,
            (byte) 0x1D, (byte) 0xF6, (byte) 0xE2, (byte) 0x2E, (byte) 0x82, (byte) 0x66, (byte) 0xCA, (byte) 0x60,
            (byte) 0xC0, (byte) 0x29, (byte) 0x23, (byte) 0xAB, (byte) 0x0D, (byte) 0x53, (byte) 0x4E, (byte) 0x6F,
            (byte) 0xD5, (byte) 0xDB, (byte) 0x37, (byte) 0x45, (byte) 0xDE, (byte) 0xFD, (byte) 0x8E, (byte) 0x2F,
            (byte) 0x03, (byte) 0xFF, (byte) 0x6A, (byte) 0x72, (byte) 0x6D, (byte) 0x6C, (byte) 0x5B, (byte) 0x51,
            (byte) 0x8D, (byte) 0x1B, (byte) 0xAF, (byte) 0x92, (byte) 0xBB, (byte) 0xDD, (byte) 0xBC, (byte) 0x7F,
            (byte) 0x11, (byte) 0xD9, (byte) 0x5C, (byte) 0x41, (byte) 0x1F, (byte) 0x10, (byte) 0x5A, (byte) 0xD8,
            (byte) 0x0A, (byte) 0xC1, (byte) 0x31, (byte) 0x88, (byte) 0xA5, (byte) 0xCD, (byte) 0x7B, (byte) 0xBD,
            (byte) 0x2D, (byte) 0x74, (byte) 0xD0, (byte) 0x12, (byte) 0xB8, (byte) 0xE5, (byte) 0xB4, (byte) 0xB0,
            (byte) 0x89, (byte) 0x69, (byte) 0x97, (byte) 0x4A, (byte) 0x0C, (byte) 0x96, (byte) 0x77, (byte) 0x7E,
            (byte) 0x65, (byte) 0xB9, (byte) 0xF1, (byte) 0x09, (byte) 0xC5, (byte) 0x6E, (byte) 0xC6, (byte) 0x84,
            (byte) 0x18, (byte) 0xF0, (byte) 0x7D, (byte) 0xEC, (byte) 0x3A, (byte) 0xDC, (byte) 0x4D, (byte) 0x20,
            (byte) 0x79, (byte) 0xEE, (byte) 0x5F, (byte) 0x3E, (byte) 0xD7, (byte) 0xCB, (byte) 0x39, (byte) 0x48
    };

    private static final int[] CK = new int[]{
            0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
            0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
            0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
            0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
            0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
            0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
            0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    private static final int[] FK = new int[]{
            0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
    };

    private final int BLOCK_SIZE = 16;

    /**
     * τtrsform
     *
     * @param input input(a0,a1,a2,a3)
     * @return τ(input)=(sbox(a0),sbox(a1),sbox(a2),sbox(a3))
     */
    private int tau(int input) {
        int lowest8bit = S_BOX[input & 255] & 255;
        int second8bit = S_BOX[(input >> 8) & 255] & 255;
        int third8bit = S_BOX[(input >> 16) & 255] & 255;
        int highest8bit = S_BOX[(input >> 24) & 255] & 255;
        second8bit = second8bit << 8;
        third8bit = third8bit << 16;
        highest8bit = highest8bit << 24;
        return lowest8bit | second8bit | third8bit | highest8bit;
    }

    /**
     * L change
     *
     * @param input
     * @return
     */
    private int l(int input) {
        return input ^
                ((input << 2) | (input >>> 30)) ^
                ((input << 10) | (input >>> 22)) ^
                ((input << 18) | (input >>> 14)) ^
                ((input << 24) | (input >>> 8));
    }

    /**
     * L' change
     *
     * @param input
     * @return
     */
    private int _l(int input) {
        return input ^ ((input << 13) | (input >>> 19)) ^ ((input << 23) | (input >>> 9));
    }

    /**
     * T change
     *
     * @param input
     * @return
     */
    private int t(int input) {
        return l(tau(input));
    }

    /**
     * T' change
     *
     * @param input
     * @return
     */
    private int _t(int input) {
        return _l(tau(input));
    }

    /**
     * F function
     *
     * @param x0
     * @param x1
     * @param x2
     * @param x3
     * @param rk0
     * @return
     */
    private int f(int x0, int x1, int x2, int x3, int rk0) {
        return x0 ^ t(x1 ^ x2 ^ x3 ^ rk0);
    }

    /**
     * reverse
     *
     * @param x32
     * @param x33
     * @param x34
     * @param x35
     * @return
     */
    private byte[] reverse(int x32, int x33, int x34, int x35) {
        byte[] output = new byte[BLOCK_SIZE];
        reverse(x32, x33, x34, x35, output, 0);
        return output;
    }

    /**
     * reverse
     *
     * @param x32
     * @param x33
     * @param x34
     * @param x35
     * @param output
     * @param outputOffset
     */
    private void reverse(int x32, int x33, int x34, int x35, byte[] output, int outputOffset) {
        intToBigEndian(output, x35, outputOffset);
        intToBigEndian(output, x34, 4 + outputOffset);
        intToBigEndian(output, x33, 8 + outputOffset);
        intToBigEndian(output, x32, 12 + outputOffset);
    }

    /**
     * convert int to 4 bytes
     *
     * @param output
     * @param x
     * @param start
     */
    public void intToBigEndian(byte[] output, int x, int start) {
        Util.intToBigEndian(x, output, start);
    }

    /**
     * convert 4 bytes to int
     *
     * @param bytes
     * @param start
     * @return
     */
    public int bigEndianToInt(byte[] bytes, int start) {
        return Util.bigEndianToInt(bytes, start);
    }

    /**
     * calculate rk
     *
     * @param key
     * @return
     */
    public int[] expandKey(byte[] key) {

        int[] rk = new int[32];

        int K0 = bigEndianToInt(key, 0) ^ FK[0];
        int K1 = bigEndianToInt(key, 4) ^ FK[1];
        int K2 = bigEndianToInt(key, 8) ^ FK[2];
        int K3 = bigEndianToInt(key, 12) ^ FK[3];

        for (int i = 0; i < rk.length; i++) {
            rk[i] = K0 ^ _t(K1 ^ K2 ^ K3 ^ CK[i]);
            K0 = K1;
            K1 = K2;
            K2 = K3;
            K3 = rk[i];
        }
        return rk;
    }

    /**
     * SM4 encrypt
     *
     * @param rk
     * @param input
     * @return
     */
    public byte[] encrypt(int[] rk, byte[] input) {
        byte[] res = new byte[BLOCK_SIZE];
        encrypt(rk, input, 0, res, 0);
        return res;
    }

    /**
     * SM4 encrypt
     *
     * @param rk
     * @param input
     * @param inputOffset
     * @return
     */
    public byte[] encrypt(int[] rk, byte[] input, int inputOffset) {
        byte[] res = new byte[BLOCK_SIZE];
        encrypt(rk, input, inputOffset, res, 0);
        return res;
    }

    /**
     * SM4 encrypt
     *
     * @param rk
     * @param input
     * @param inputOffset
     * @param output
     * @param outputOffset
     */
    public void encrypt(int[] rk, byte[] input, int inputOffset, byte[] output, int outputOffset) {
        int x0 = bigEndianToInt(input, inputOffset);
        int x1 = bigEndianToInt(input, 4 + inputOffset);
        int x2 = bigEndianToInt(input, 8 + inputOffset);
        int x3 = bigEndianToInt(input, 12 + inputOffset);

        for (int i = 0; i < rk.length; i++) {
            int res = f(x0, x1, x2, x3, rk[i]);
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = res;
        }

        reverse(x0, x1, x2, x3, output, outputOffset);
    }

    /**
     * SM4 decrypt
     *
     * @param rk
     * @param cipherText
     * @return
     */
    public byte[] decrypt(int[] rk, byte[] cipherText) {
        byte[] res = new byte[BLOCK_SIZE];
        decrypt(rk, cipherText, 0, res, 0);
        return res;
    }

    /**
     * SM4 decrypt
     *
     * @param rk
     * @param input
     * @param inputOffset
     * @return
     */
    public byte[] decrypt(int[] rk, byte[] input, int inputOffset) {
        byte[] res = new byte[BLOCK_SIZE];
        decrypt(rk, input, inputOffset, res, 0);
        return res;
    }

    /**
     * SM4 decrypt
     *
     * @param rk
     * @param input
     * @param inputOffset
     * @param output
     * @param outputOffset
     */
    public void decrypt(int[] rk, byte[] input, int inputOffset, byte[] output, int outputOffset) {

        int x0 = bigEndianToInt(input, inputOffset);
        int x1 = bigEndianToInt(input, 4 + inputOffset);
        int x2 = bigEndianToInt(input, 8 + inputOffset);
        int x3 = bigEndianToInt(input, 12 + inputOffset);

        for (int i = rk.length - 1; i >= 0; i--) {

            int res = f(x0, x1, x2, x3, rk[i]);
            x0 = x1;
            x1 = x2;
            x2 = x3;
            x3 = res;

        }
        reverse(x0, x1, x2, x3, output, outputOffset);
    }


    /**
     * xor operation
     *
     * @param b1
     * @param b2
     * @return the result of XOR of the shorter array and the corresponding part of the longer array
     */
    public byte[] xor(byte[] b1, byte[] b2) {
        if (b1 == null || b2 == null) {
            return null;
        }
        byte[] res = new byte[Math.min(b1.length, b2.length)];
        for (int i = 0; i < res.length; i++) {
            res[i] = (byte) (b1[i] ^ b2[i]);
        }
        return res;
    }

    /**
     * xor operation
     *
     * @param b1
     * @param from1 b1's start index
     * @param len1
     * @param b2
     * @param from2 b2's start index
     * @param len2
     * @return the result of XOR of the shorter array and the corresponding part of the longer array
     */
    public byte[] xor(byte[] b1, int from1, int len1, byte[] b2, int from2, int len2) {
        if (b1 == null || b2 == null) {
            return null;
        }
        byte[] res = new byte[Math.min(len1, len2)];
        for (int i = 0; i < res.length; i++) {
            res[i] = (byte) (b1[i + from1] ^ b2[i + from2]);
        }
        return res;
    }

    /**
     * xor operation
     *
     * @param b1
     * @param b2
     * @return 16 bytes result of b1 xor b2 if b1.length<16 when i>b1.length res[i]= b2[i]^0 = b2[i];
     */
    public byte[] xor16Byte(byte[] b1, byte[] b2) {
        if (b1 == null || b2 == null) {
            return null;
        }
        if (b1.length != 16 && b2.length != 16) {
            return null;
        }
        byte[] res = new byte[16];
        int len = Math.min(b1.length, b2.length);
        for (int i = 0; i < len; i++) {
            res[i] = (byte) (b1[i] ^ b2[i]);
        }
        if (b1.length != b2.length) {
            int longLen = len == b1.length ? b2.length : b1.length;
            byte[] longArr = longLen == b1.length ? b1 : b2;
            System.arraycopy(longArr, len, res, len, longLen - len);
        }
        return res;
    }

    /**
     * copy the input from inputOffset into the output
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    public static void copyArray(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        System.arraycopy(input, inputOffset, output, outputOffset, inputLen);
    }

}
