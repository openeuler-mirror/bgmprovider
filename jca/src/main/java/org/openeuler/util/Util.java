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

import java.math.BigInteger;
import java.security.SecureRandom;

public class Util {
    /**
     * 32-bit cyclic shift left by k bits
     * @param x 32-bit number
     * @param k The number of bits that need to be rotated left
     * @return (x << k) | (x >>> (32 - k))
     */
    public static int rotateShiftLeft(int x, int k) {
        return (x << k) | (x >>> (32 - k));
    }

    /**
     * convert the numbers to big endian
     * @param ns  list of numbers
     * @param bs  Byte array to store converted numbers
     * @param off start position of bit array
     */
    public static void intToBigEndian(int[] ns, byte[] bs, int off) {
        for (int n : ns) {
            intToBigEndian(n, bs, off);
            off += 4;
        }
    }

    /**
     * convert the number to big endian
     * @param n   number
     * @param bs  Byte array to store converted numbers
     * @param off start position of bit array
     */
    public static void intToBigEndian(int n, byte[] bs, int off) {
        bs[off] = (byte) (n >>> 24);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n);
    }


    public static int bigEndianToInt(byte[] bs, int off) {
        int n = bs[off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff);
        return n;
    }

    /**
     * Create a large integer of a specific bit length
     *
     * @param bitLen
     * @param random
     * @return A Biginteger with a bit length of bitLen
     */
    public static BigInteger createRandomBigInteger(int bitLen, SecureRandom random) {
        byte[] randomBytes = createRandom(bitLen, random);
        return new BigInteger(1, randomBytes);
    }

    /**
     * Create a large integer of a specific bit length
     *
     * @param bitLen
     * @param random
     * @return A byte array of a Biginteger with a bit length of bitLen
     * @throws IllegalArgumentException
     */
    private static byte[] createRandom(int bitLen, SecureRandom random)
            throws IllegalArgumentException {
        if (bitLen < 1) {
            throw new IllegalArgumentException("The bit length must be at least 1");
        }

        int byteLen = (bitLen + 7) / 8;
        byte[] randomBytes = new byte[byteLen];
        if (random == null) {
            random = new SecureRandom();
        }
        random.nextBytes(randomBytes);
        int xBits = 8 * byteLen - bitLen;
        randomBytes[0] &= (byte) (255 >>> xBits);

        return randomBytes;
    }

    /**
     * Return the passed in value as an unsigned byte array of the specified length, padded with
     * leading zeros as necessary..
     *
     * @param length the fixed length of the result
     * @param value  the value to be converted.
     * @return a byte array padded to a fixed length with leading zeros.
     */
    public static byte[] asUnsignedByteArray(int length, BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }

        int start = (bytes[0] == 0 && bytes.length != 1) ? 1 : 0;
        int count = bytes.length - start;

        if (count > length) {
            throw new IllegalArgumentException("standard length exceeded for value");
        }

        byte[] tmp = new byte[length];
        System.arraycopy(bytes, start, tmp, tmp.length - count, count);
        return tmp;
    }

    /**
     * Concatenate byte arrays a and b
     *
     * @param a
     * @param b
     * @return the resulting array after concatenating the input arrays
     */
    public static byte[] concatenate(byte[] a, byte[] b) {
        if (null == a) {
            // b might also be null
            return null == b ? null : b.clone();
        }
        if (null == b) {
            // a might also be null
            return null == a ? null : a.clone();
        }

        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /**
     * Concatenate byte arrays a, b and c
     *
     * @param a
     * @param b
     * @param c
     * @return the resulting array after concatenating the input arrays
     */
    public static byte[] concatenate(byte[] a, byte[] b, byte[] c) {
        if (null == a) {
            return concatenate(b, c);
        }
        if (null == b) {
            return concatenate(a, c);
        }
        if (null == c) {
            return concatenate(a, b);
        }

        byte[] r = new byte[a.length + b.length + c.length];
        int pos = 0;
        System.arraycopy(a, 0, r, pos, a.length);
        pos += a.length;
        System.arraycopy(b, 0, r, pos, b.length);
        pos += b.length;
        System.arraycopy(c, 0, r, pos, c.length);
        return r;
    }

    /**
     * A locale independent version of toUpperCase.
     *
     * @param string input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            char ch = chars[i];
            if ('a' <= ch && 'z' >= ch) {
                changed = true;
                chars[i] = (char) (ch - 'a' + 'A');
            }
        }

        if (changed) {
            return new String(chars);
        }

        return string;
    }
}
