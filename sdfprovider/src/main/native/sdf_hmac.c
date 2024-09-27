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
#include "org_openeuler_sdf_wrapper_SDFHmacNative.h"
#include "sdf.h"
#include "sdf_exception.h"
#include "sdf_util.h"

#include <string.h>
#include <malloc.h>

/*
 * Class:     org_openeuler_sdf_wrapper_SDFHmacNative
 * Method:    nativeHmacInit
 * Signature: (J[BLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacInit
        (JNIEnv *env, jclass cls, jlong sessionAddress, jbyteArray keyBytes, jstring digestName) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionAddress;
    unsigned char *uiKey = NULL;
    unsigned int uiKeyLen;
    SGD_HANDLE hKeyHandle = NULL;

    const char *digestNameChars = NULL;
    unsigned int uiAlgID;

    unsigned int uiType = SDF_CTX_TYPE_HMAC;
    void *HMAC_CONTEXT = NULL;

    SGD_RV rv = SDR_UNKNOWERR;

    // hKeyHandle
    uiKeyLen = (*env)->GetArrayLength(env, keyBytes);
    if ((uiKey = malloc(uiKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc uiKey failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, keyBytes, 0, uiKeyLen, uiKey);

    // Import encrypted uiKey
    if ((rv = SDF_HW_ImportKey(hSessionHandle, uiKey, uiKeyLen, &hKeyHandle)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    // new HMAC_CONTEXT
    if ((rv = SDF_HW_MemoryCalloc(hSessionHandle, uiType, &HMAC_CONTEXT)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    // hmac init
    digestNameChars = (*env)->GetStringUTFChars(env, digestName, 0);
    uiAlgID = SDF_GetDigestAlgoId(digestNameChars);
    if (uiAlgID == SDF_INVALID_VALUE) {
        throwIllegalArgumentException(env, "invalid digestName");
        goto cleanup;
    }
    rv = SDF_HW_HmacInit(hSessionHandle, hKeyHandle, uiAlgID, HMAC_CONTEXT);
    if (rv != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

cleanup:
    if (uiKey != NULL) {
        free(uiKey);
    }
    if (digestNameChars != NULL) {
        (*env)->ReleaseStringUTFChars(env, digestName, digestNameChars);
    }
    // hKeyHandle can be free after SDF_HW_HmacInit
    if (hKeyHandle != NULL) {
        SDF_DestroyKey(hSessionHandle, hKeyHandle);
    }
    if (rv != SDR_OK && HMAC_CONTEXT != NULL) {
        SDF_HW_MemoryFree(hSessionHandle, uiType, HMAC_CONTEXT);
    }
    return (jlong) HMAC_CONTEXT;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFHmacNative
 * Method:    nativeHmacUpdate
 * Signature: (J[BIJ)V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacUpdate
        (JNIEnv *env, jclass cls, jlong sessionAddress, jlong ctxAddress, jbyteArray input, jint offset, jint len) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionAddress;
    void *HMAC_CONTEXT = (void *) ctxAddress;
    unsigned char *pucData = NULL;
    unsigned int uiDataLength = len;
    SGD_RV rv;

    if (!(pucData = malloc(uiDataLength))) {
        throwOutOfMemoryError(env, "malloc pucData failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, input, offset, len, pucData);

    if ((rv = SDF_HW_HmacUpdate(hSessionHandle, pucData, uiDataLength, HMAC_CONTEXT)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

cleanup:
    if (pucData != NULL) {
        free(pucData);
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFHmacNative
 * Method:    nativeHmacFinal
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacFinal
        (JNIEnv *env, jclass cls, jlong sessionAddress, jlong ctxAddress, jint macLen) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionAddress;
    void *HMAC_CONTEXT = (void *) ctxAddress;
    unsigned char *pucHmac = NULL;
    unsigned int puiHmacLength;
    jbyteArray byteArray = NULL;
    SGD_RV rv;

    if (!(pucHmac = malloc(macLen))) {
        throwOutOfMemoryError(env, "malloc pucHmac failed");
        goto cleanup;
    }

    if ((rv = SDF_HW_HmacFinal(hSessionHandle, pucHmac, &puiHmacLength, HMAC_CONTEXT)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    byteArray = (*env)->NewByteArray(env, (jsize) puiHmacLength);
    (*env)->SetByteArrayRegion(env, byteArray, 0, puiHmacLength, pucHmac);

cleanup:
    if (pucHmac != NULL) {
        free(pucHmac);
    }
    return byteArray;
}


/*
 * Class:     org_openeuler_sdf_wrapper_SDFHmacNative
 * Method:    nativeHmacContextFree
 * Signature: (JJ)[B
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacContextFree
        (JNIEnv *env, jclass cls, jlong sessionAddress, jlong ctxAddress) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionAddress;
    unsigned int uiType = SDF_CTX_TYPE_HMAC;
    void *HMAC_CONTEXT = (void *) ctxAddress;
    SGD_RV rv;

    if (HMAC_CONTEXT == NULL) {
        return;
    }

    if ((rv = SDF_HW_MemoryFree(hSessionHandle, uiType, HMAC_CONTEXT)) != SDR_OK) {
        throwSDFException(env, rv);
        return;
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFHmacNative
 * Method:    nativeHmacContextClone
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacContextClone
        (JNIEnv *env, jclass cls, jlong sessionAddress, jlong ctxAddress) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionAddress;
    unsigned int uiType = SDF_CTX_TYPE_HMAC;
    void *uiSrcHandle = (void *) ctxAddress;
    void *uiDestHandle = NULL;
    SGD_RV rv;

    if ((rv = SDF_HW_MemoryCalloc(hSessionHandle, uiType, &uiDestHandle) != SDR_OK)) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    if ((rv = SDF_HW_MemoryCopy(hSessionHandle, uiType, uiSrcHandle, uiDestHandle)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }
cleanup:
    return (jlong) (uiDestHandle);
}