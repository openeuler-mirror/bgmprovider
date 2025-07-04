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


package org.openeuler.sdf.commons.util;

public enum SDFKeyTestDB {
    SM1_KEY("SM1",
            new byte[]{-78, 13, -71, 96, 114, 81, 24, -77, -88, -29, -102, -80, 100, 78, 115, -107}),
    SM4_KEY("SM4",
            new byte[]{-78, 13, -71, 96, 114, 81, 24, -77, -88, -29, -102, -80, 100, 78, 115, -107}),


    HMAC_SM3_KEY("HmacSM3", new byte[]{
            88, -44, -67, 37, 44, 1, 123, -99, -14, -77, -126, -117, 36, -80, 33, -17, 50,
            -97, -8, -105, 51, 102, -1, -87, 10, 24, -11, -45, 70, 53, -113, -100}
    ),

    SM2_KEY_PAIR("SM2", new byte[]{
            57, 14, 81, -67, 109, -49, -65, -72, -63, -60, 59, -49, -108, -70, -51, -10, -46, 30, -110, -11, -78, -80, -113, 29, 106, -95, 86, -25, -35, 113, 16, -92
    }, new byte[]{
            48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -127, 28, -49, 85, 1, -126, 45, 3, 66, 0, 4, -22, -87, 78, 0, 18, 66, 120, 91, -121, -43, -93, 6, 0, -15, 79, 108, 52, -49, 32, 95, -109, 81, 82, -122, 33, 13, -13, 102, 24, 50, -71, 62, -24, 93, -60, 127, -98, -29, -113, -21, -22, -93, -22, -99, 80, -80, -54, -51, 19, -87, -113, 41, 29, -113, 62, 104, 76, 4, 18, 55, -60, 7, -12, -98
    });

    final String algorithm;
    final byte[] plainKey;
    final byte[] encKey;
    byte[] pubKey;

    SDFKeyTestDB(String algorithm, byte[] plainKey) {
        this.algorithm = algorithm;
        this.plainKey = plainKey;
        this.encKey = SDFTestEncKeyGenUtil.encKey(algorithm, plainKey);
    }

    SDFKeyTestDB(String algorithm, byte[] plainKey, byte[] pubKey) {
        this(algorithm, plainKey);
        this.pubKey = pubKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getPlainKey() {
        return plainKey;
    }

    public byte[] getEncKey() {
        return encKey;
    }

    public byte[] getPubKey() {
        return pubKey;
    }
}
