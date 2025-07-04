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

package org.openeuler.sdf.jca.commons;

import java.math.BigInteger;
import java.security.spec.*;
import java.util.HashMap;
import java.util.Map;

public class SDFCurveUtil {
    private static final Map<Integer, String> SIZE_TO_CURVE = new HashMap<>();
    private static final Map<String, String> CURVE_ALIAS = new HashMap<>();

    private static final EllipticCurve SM2_CURVE = new EllipticCurve(
            new ECFieldFp(
                    new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
            ),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
            new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16));

    static {
        initCurve();
    }

    private static void initCurve() {
        CURVE_ALIAS.put("sm2p256v1", "SM2");
        CURVE_ALIAS.put("1.2.156.10197.1.301", "SM2");
    }

    public static boolean isSM2Curve(AlgorithmParameterSpec params) {
        if (params instanceof ECParameterSpec) {
            EllipticCurve curve = ((ECParameterSpec) params).getCurve();
            return isSM2Curve(curve);
        } else if (params instanceof ECGenParameterSpec) {
            ECGenParameterSpec genParameterSpec = (ECGenParameterSpec) params;
            return CURVE_ALIAS.containsKey(genParameterSpec.getName());
        }
        return false;
    }

    public static boolean isSM2Curve(EllipticCurve curve) {
        return SM2_CURVE.equals(curve);
    }
}
