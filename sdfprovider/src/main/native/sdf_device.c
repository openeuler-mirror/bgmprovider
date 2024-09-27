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

#include "org_openeuler_sdf_wrapper_SDFDeviceNative.h"
#include "sdf.h"
#include "sdf_exception.h"

/*
 * Class:     org_openeuler_sdf_wrapper_SDFDeviceNative
 * Method:    nativeOpenDevice
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFDeviceNative_nativeOpenDevice
        (JNIEnv *env, jclass cls) {
    SGD_HANDLE deviceHandle = NULL;
    SGD_RV rv = SDF_HW_OpenDevice(&deviceHandle, NULL, 0, NULL, 0) ;
    if (rv != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    return (jlong) deviceHandle;
    cleanup:
    if (deviceHandle)
        SDF_CloseDevice(deviceHandle);
    return 0;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFDeviceNative
 * Method:    nativeCloseDevice
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFDeviceNative_nativeCloseDevice
        (JNIEnv *env, jclass cls, jlong hDeviceHandle) {
    SGD_HANDLE deviceHandle = (SGD_HANDLE) hDeviceHandle;
    SGD_RV rv = SDF_CloseDevice(deviceHandle);
    if (rv != 0) {
        throwSDFException(env, rv);
    }
}