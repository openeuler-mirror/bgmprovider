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

#include "cryptocard/crypto_sdk_pf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFKeyGeneratorNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFKeyGeneratorNative_nativeGenerateSecretKey (
        JNIEnv *env, jclass cls, jbyteArray kekIdArr, jbyteArray regionIdArr, jbyteArray cdpIdArr,
        jbyteArray pinArr, jstring algoName,jint keySize, jboolean isHmac, jboolean isXts) {
    const char *algoNameUTF = NULL;
    unsigned int algId = ALG_SM4;
    unsigned int ivLen = 16;
    unsigned char iv[ivLen];
    unsigned int keyType;
    unsigned int xtsFlag;
    unsigned int encKeyLen = 0 ;
    unsigned char *encKey = NULL;
    void *dekParams = NULL;
    jbyteArray encKeyArr = NULL;
    SGD_RV rv;

    // get keyType
    algoNameUTF = (*env)->GetStringUTFChars(env, algoName, 0);
    if (isHmac) {
        keyType = SDF_GetHmacKeyType(algoNameUTF);
    } else {
        keyType = SDF_GetSymmetricKeyType(algoNameUTF);
    }
    if (isXts) {
        xtsFlag = 1;
    } else {
        xtsFlag = 0;
    }

    // generate iv
    if ((rv = CDM_GenRandom(ivLen, iv)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_GenRandom");
        goto cleanup;
    }

    // create dek params
    if (!(dekParams = SDF_CreateDEKParams(env, kekIdArr, regionIdArr, cdpIdArr, pinArr))) {
        goto cleanup;
    }

    // compute key size
    if ((rv = CDM_CreateDataKeyWithoutPlaintext(algId, iv, ivLen, dekParams,
            keyType, xtsFlag, keySize, encKey, &encKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDataKeyWithoutPlaintext");
        goto cleanup;
    }
    if (!(encKey = malloc(encKeyLen))) {
        throwOutOfMemoryError(env, "malloc enckey failed");
        goto cleanup;
    }

    if ((rv = CDM_CreateDataKeyWithoutPlaintext(algId, iv, ivLen, dekParams,
            keyType, xtsFlag, keySize, encKey, &encKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDataKeyWithoutPlaintext");
        goto cleanup;
    }

    encKeyArr = (*env)->NewByteArray(env, encKeyLen);
    (*env)->SetByteArrayRegion(env, encKeyArr, 0, encKeyLen, (jbyte *) encKey);

cleanup:
    if (algoNameUTF) {
        (*env)->ReleaseStringUTFChars(env, algoName, algoNameUTF);
    }
    if (encKey) {
        free(encKey);
    }
    SDF_FreeDEKParams(env, dekParams);
    return encKeyArr;
}