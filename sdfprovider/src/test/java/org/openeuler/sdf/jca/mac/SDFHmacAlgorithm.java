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

package org.openeuler.sdf.jca.mac;

enum SDFHmacAlgorithm {
        HmacSM3("HmacSM3", true, null, "Hmac Test",
                "", 32),
       HmacMD5("HmacMD5", false, null, "Hmac Test",
                "", 16),
        HmacSHA1("HmacSHA1", false, new String[]{"1.2.840.113549.2.7"}, "Hmac Test",
                "", 20),
        HmacSHA224("HmacSHA224", false, new String[]{"1.2.840.113549.2.8"}, "Hmac Test",
                "", 28),
        HmacSHA256("HmacSHA256", false, new String[]{"1.2.840.113549.2.9"}, "Hmac Test",
                "", 32),
        HmacSHA384("HmacSHA384", false, new String[]{"1.2.840.113549.2.10"}, "Hmac Test",
                "", 48),
        HmacSHA512("HmacSHA512", false, new String[]{"1.2.840.113549.2.11"}, "Hmac Test",
                "", 64);

        final String algoName;
        final boolean isSM;
        final String[] algoAliases;
        final String plainText;
        final String macValue;
        final int macLen;
        final int defaultPlainKeySize;

        SDFHmacAlgorithm(String algoName, boolean isSM, String[] algoAliases,
                         String plainText, String macValue, int macLen) {
            this.algoName = algoName;
            this.isSM = isSM;
            this.algoAliases = algoAliases;
            this.plainText = plainText;
            this.macValue = macValue;
            this.macLen = macLen;
            this.defaultPlainKeySize = macLen;
        }
    }
