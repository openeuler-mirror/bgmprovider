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

public class SDFDigestNative {

    // return pointer to the context
    public native static long nativeDigestInit(String algorithmName);

    // update the input byte
    public native static void nativeDigestUpdate(long ctxAddress, byte[] input, int offset, int inLen);

    // digest and store the digest message to output
    public native static byte[] nativeDigestFinal(long ctxAddress, int digestLen);

    // free the digest context
    public native static void nativeDigestCtxFree(long ctxAddress);

    // clone the digest context
    public native static long nativeDigestCtxClone(long ctxAddress);
}
