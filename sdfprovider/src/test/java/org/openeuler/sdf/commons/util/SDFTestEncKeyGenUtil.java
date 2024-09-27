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

import org.openeuler.sdf.commons.session.SDFSession;
import org.openeuler.sdf.commons.session.SDFSessionManager;
import org.openeuler.sdf.wrapper.SDFInternalNative;

import static org.openeuler.sdf.commons.util.SDFTestEncKeyGenUtil.SDFTestKeyType.HW_HMAC;
import static org.openeuler.sdf.commons.util.SDFTestEncKeyGenUtil.SDFTestKeyType.HW_SYM;

public class SDFTestEncKeyGenUtil {
    enum SDFTestKeyType {
        HW_SM2(0),
        HW_RSA(1),
        HW_ECC(2),
        HW_SM9(3),
        HW_SYM(4),
        HW_HMAC(5);
        final int type;

        SDFTestKeyType(int type) {
            this.type = type;
        }

        public int getType() {
            return type;
        }
    }

    public static byte[] encKey(String algorithm, byte[] plainKey) {
        algorithm = algorithm.toUpperCase();
        if ("SM1".equals(algorithm) || "SM4".equals(algorithm) || "SM7".equals(algorithm)) {
            return encSymmetricKey(plainKey);
        }
        if (algorithm.startsWith("HMAC")) {
            return encHmacKey(plainKey);
        }
        throw new IllegalArgumentException("Not support " + algorithm);
    }
    public static byte[] encKey(SDFTestKeyType uiType, byte[] plainKey) {
        SDFSession session = SDFSessionManager.getInstance().getSession();
        return SDFInternalNative.encryptKey(session.getAddress(),
                SDFTestUtil.getTestKekId(),
                SDFTestUtil.getTestRegionId(),
                SDFTestUtil.getTestCdpId(),
                SDFTestUtil.getTestPin(),
                uiType.getType(),
                plainKey
        );
    }

    public static byte[] encSymmetricKey(byte[] plainKey) {
        return encKey(HW_SYM, plainKey);
    }

    public static byte[] encHmacKey(byte[] plainKey) {
        return encKey(HW_HMAC, plainKey);
    }
}
