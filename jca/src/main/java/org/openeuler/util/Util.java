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

package org.openeuler.util;

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
     * @param ns list of numbers
     * @param bs Byte array to store converted numbers
     * @param off start position of bit array
     */
    public static void intToBigEndian(int[] ns, byte[] bs, int off)
    {
        for (int n : ns) {
            intToBigEndian(n, bs, off);
            off += 4;
        }
    }

    /**
     * convert the number to big endian
     * @param n number
     * @param bs Byte array to store converted numbers
     * @param off start position of bit array
     */
    public static void intToBigEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n);
    }
}
