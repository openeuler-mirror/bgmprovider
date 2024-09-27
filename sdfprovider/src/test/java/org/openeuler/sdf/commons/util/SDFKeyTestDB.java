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
            );

    final String algorithm;
    final byte[] plainKey;
    final byte[] encKey;

    SDFKeyTestDB(String algorithm, byte[] plainKey) {
        this.algorithm = algorithm;
        this.plainKey = plainKey;
        this.encKey = SDFTestEncKeyGenUtil.encKey(algorithm, plainKey);
    }

    SDFKeyTestDB(String algorithm, byte[] plainKey, byte[] encKey) {
        this.algorithm = algorithm;
        this.plainKey = plainKey;
        this.encKey = encKey;
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
}
