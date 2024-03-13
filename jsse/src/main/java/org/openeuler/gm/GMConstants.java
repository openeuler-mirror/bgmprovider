/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.gm;

import java.util.*;

public class GMConstants {
    private static final Map<String, GMAlgorithm> GM_ALG_MAP = new HashMap<>();

    public static final String SM2 = "SM2";
    public static final String SM3_WITH_SM2 = "SM3withSM2";
    public static final String SM3_WITH_SM2_OID = "1.2.156.10197.1.501";
    public static final String EC = "EC";

    /**
     * The SM2 signature algorithm requests an identifier value when generating or verifying a signature.
     * In all uses except when a client of a server needs to verify a peer's SM2 certificate in the
     * Certificate message, an implementation of this document MUST use the following ASCII string value
     * as the SM2 identifier when doing a TLS 1.3 key exchange:
     * <p>
     * TLSv1.3+GM+Cipher+Suite
     * </p>
     */
    public static final byte[] TLS13_GM_ID = {
            0x54, 0x4c, 0x53, 0x76, 0x31, 0x2e, 0x33, 0x2b,
            0x47, 0x4d, 0x2b, 0x43, 0x69, 0x70, 0x68, 0x65,
            0x72, 0x2b, 0x53, 0x75, 0x69, 0x74, 0x65
    };

    static {
        initGMAlgorithmMap();
    }

    /**
     * Init GM_ALGORITHM_MAP.
     */
    private static void initGMAlgorithmMap() {
        GMAlgorithm[] gmAlgorithms = GMAlgorithm.values();
        for (GMAlgorithm gmAlgorithm : gmAlgorithms) {
            GM_ALG_MAP.put(gmAlgorithm.name().toUpperCase(Locale.ENGLISH), gmAlgorithm);
        }
    }

    /**
     * GM algorithm
     */
    enum GMAlgorithm {
        SM2(new HashSet<>(
                Arrays.asList(GMConstants.SM2.toUpperCase(Locale.ENGLISH),
                        GMConstants.EC.toUpperCase(Locale.ENGLISH)))
        ),
        SM3withSM2(new HashSet<>(
                Arrays.asList(GMConstants.SM3_WITH_SM2.toUpperCase(Locale.ENGLISH),
                        GMConstants.SM3_WITH_SM2_OID.toUpperCase(Locale.ENGLISH)))
        );

        // algorithm names
        private final Set<String> algNames;

        GMAlgorithm(Set<String> algNames) {
            this.algNames = algNames;
        }

        boolean equals(String algorithm) {
            if (algorithm == null) {
                return false;
            }
            return algNames.contains(algorithm.toUpperCase(Locale.ENGLISH));
        }
    }

    /**
     * Check whether the algorithm is the same.
     * Used for compatibility when the algorithm has multiple aliases, such as SM2, SM3withSM2.
     * If expectedAlg is in GMAlgorithm, use GMAlgorithm.equals method to compare.
     * Otherwise, use String.equals method to compare.
     *
     * @see GMAlgorithm#equals(String)
     * @see String#equals(Object)
     */
    public static boolean equalsAlgorithm(String expectedAlg, String alg) {
        if (expectedAlg == null) {
            return alg == null;
        }
        GMAlgorithm gmAlgorithm = GM_ALG_MAP.get(expectedAlg.toUpperCase(Locale.ENGLISH));
        return gmAlgorithm != null ? gmAlgorithm.equals(alg) : expectedAlg.equals(alg);
    }
}
