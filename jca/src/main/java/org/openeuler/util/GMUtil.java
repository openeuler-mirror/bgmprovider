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

import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class GMUtil {

    private static final Set<String> SM2_CURVE_NAMES = new HashSet<>(
            Arrays.asList("sm2p256v1", "1.2.156.10197.1.301",
                    "wapip192v1", "1.2.156.10197.1.301.101"));

    public static boolean isGMCurve(AlgorithmParameterSpec params) {
        ECGenParameterSpec genParameterSpec = null;
        if (params instanceof ECParameterSpec) {
            AlgorithmParameters ecParameters = ECUtil.getECParameters(null);
            try {
                ecParameters.init(params);
                genParameterSpec = ecParameters.getParameterSpec(ECGenParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                // skip
            }
        } else if (params instanceof ECGenParameterSpec) {
            genParameterSpec = (ECGenParameterSpec) params;
        }
        return genParameterSpec != null && SM2_CURVE_NAMES.contains(genParameterSpec.getName());
    }
}
