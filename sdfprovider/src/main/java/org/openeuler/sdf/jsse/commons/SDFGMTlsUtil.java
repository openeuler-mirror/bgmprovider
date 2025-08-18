/*
 * Copyright (c) 2025, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.jsse.commons;

public class SDFGMTlsUtil {
    /*
     * Determine whether it is an invalid EC certificate.
     */
    public static boolean isInvalidECCert(String keyType, String sigAlgName) {
        // If the keyType is EC, filter the certificate of the signature algorithm SM3withSM2.
        return keyType.equals(SDFGMConstants.EC) && SDFGMConstants.equalsAlgorithm(
                SDFGMConstants.SM3_WITH_SM2, sigAlgName);
    }

    /*
     * Determine whether it is an invalid SM2 certificate.
     */
    public static boolean isInvalidSM2Cert(String keyType, String sigAlgName) {
        return keyType.equals(SDFGMConstants.SM2) && !SDFGMConstants.equalsAlgorithm(
                SDFGMConstants.SM3_WITH_SM2, sigAlgName);
    }

    /*
     * Determine whether it is an invalid EC or SM2 certificate.
     */
    public static boolean isInvalidECOrSM2Cert(String keyType, String sigAlgName) {
        return isInvalidECCert(keyType, sigAlgName) || isInvalidSM2Cert(keyType, sigAlgName);
    }
}
