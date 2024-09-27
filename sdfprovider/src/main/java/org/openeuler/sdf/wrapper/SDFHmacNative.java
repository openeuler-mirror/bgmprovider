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

import org.openeuler.sdf.commons.exception.SDFException;

public class SDFHmacNative {
    public static native long nativeHmacInit(long sessionAddress, byte[] keyBytes,
                                             String digestName) throws SDFException;

    public static native void nativeHmacUpdate(long sessionAddress, long ctxAddress,
                                               byte[] input, int offset, int len) throws SDFException;

    public static native byte[] nativeHmacFinal(long sessionAddress, long ctxAddress, int macLen)
            throws SDFException;

    public static native void nativeHmacContextFree(long sessionAddress, long ctxAddress) throws SDFException;

    public static native long nativeHmacContextClone(long sessionAddress, long ctxAddress) throws SDFException;
}
