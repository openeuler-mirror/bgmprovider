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

import org.openeuler.sdf.wrapper.SDFInternalNative;

import java.util.HashMap;
import java.util.Map;

public class SDFTestEncKeyGenUtil {
    private enum SDFTestKeyType {
        DATA_KEY_SM2("SM2",0),
        DATA_KEY_RSA("RSA",1),
        DATA_KEY_ECC("ECC",2),
        DATA_KEY_SM4("SM4",3),
        DATA_KEY_SM1("SM1",4),
        DATA_KEY_SM7("SM7",5),
        DATA_KEY_AES("AES",6),
        DATA_KEY_3DES("3DES",7),
        DATA_KEY_HMAC_SM3("HmacSM3",8),
        DATA_KEY_HMAC_SHA1("HmacSHA1",9),
        DATA_KEY_HMAC_SHA224("HmacSHA224",10),
        DATA_KEY_HMAC_SHA256("HmacSHA256",11),
        DATA_KEY_HMAC_SHA384("HmacSHA384",12),
        DATA_KEY_HMAC_SHA512("HmacSHA512",13),
        DATA_KEY_SM9_MASTER_SIGN("SM9MasterSign",14),
        DATA_KEY_SM9_MASTER_ENC("SM9MasterEnc",15),
        DATA_KEY_SM9_USER_SIGN("SM9UserSign",16),
        DATA_KEY_SM9_USER_ENC("SM9UserEnc",17);
        final String algorithm;
        final int type;

        SDFTestKeyType(String algorithm, int type) {
            this.algorithm = algorithm;
            this.type = type;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public int getType() {
            return type;
        }
    }

    private static final Map<String, SDFTestKeyType> keyTypeMap = new HashMap<>();
    static  {
        init();
    }
    static void init() {
        SDFTestKeyType[] sdfTestKeyTypes = SDFTestKeyType.values();
        for (SDFTestKeyType sdfTestKeyType : sdfTestKeyTypes) {
            keyTypeMap.put(sdfTestKeyType.algorithm.toUpperCase(), sdfTestKeyType);
        }
    }

    public static byte[] encKey(String algorithm, byte[] plainKey) {
        algorithm = algorithm.toUpperCase();
        SDFTestKeyType sdfTestKeyType = keyTypeMap.get(algorithm);
        if (sdfTestKeyType == null) {
            throw new IllegalArgumentException("Not support " + algorithm);
        }
        return encKey(sdfTestKeyType, plainKey);
    }

    private static byte[] encKey(SDFTestKeyType uiType, byte[] plainKey) {
        return SDFInternalNative.encryptKey(
                SDFTestUtil.getTestKekId(),
                SDFTestUtil.getTestRegionId(),
                SDFTestUtil.getTestCdpId(),
                SDFTestUtil.getTestPin(),
                uiType.getType(),
                plainKey
        );
    }
}
