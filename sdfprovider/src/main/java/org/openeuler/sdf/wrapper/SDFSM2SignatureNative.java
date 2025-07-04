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

package org.openeuler.sdf.wrapper;

public class SDFSM2SignatureNative {

    /**
     * SM2 sign
     * @param privateKeyArray private key in bytes
     * @param digestArray sm3 digest bytes
     * @return sm2 signature params
     * format {
     *     r[32],
     *     s[32]
     * }
     */
    public static native byte[][] nativeSM2Sign(byte[] privateKeyArray, byte[] digestArray);

    /**
     * SM2 verify
     * @param pubKeyArr public key x, y
     * @param digestArray sm3 digest bytes
     * @param signatureParams sm2 signature params
     * @return true if the signature was verified, false if not.
     */
    public static native boolean nativeSM2Verify(Object[] pubKeyArr, byte[] digestArray, byte[][] signatureParams);
}
