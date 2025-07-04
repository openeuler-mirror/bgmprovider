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
#include "cryptocard/crypto_sdk_vf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFSDKNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSDKNative
 * Method:    init
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFSDKNative_init
        (JNIEnv *env, jclass clazz, jstring configPathStr) {
    const char *configPath = NULL;
    SGD_RV rv;

    if (configPathStr) {
        configPath = (*env)->GetStringUTFChars(env, configPathStr, 0);
    }
    if ((rv = CDM_InitSDK(configPath)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_InitSDK");
        goto cleanup;
    }
cleanup:
    if(configPath) {
        (*env)->ReleaseStringUTFChars(env, configPathStr, configPath);
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSDKNative
 * Method:    destroy
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFSDKNative_destroy
        (JNIEnv *env, jclass clazz) {
    CDM_DeInitSDK();
}