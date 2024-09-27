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

#include "org_openeuler_sdf_wrapper_SDFDigestNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf.h"
#include <string.h>

/*
 * Class:     org_openeuler_sdf_wrapper_SDFDigestNative
 * Method:    nativeDigestInit
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestInit(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jstring algorithmName) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned int uiType = SDF_CTX_TYPE_DIGEST;
    unsigned int uiAlgID;
    void *HASH_CONTEXT = NULL;
    unsigned char *uiPublicKey = NULL;
    unsigned int uiPBKLen = 0;
    unsigned char *pucID = NULL;
    unsigned int uiIDLength = 0;
    const char *algoUtf = NULL;
    SGD_RV rv;

    jboolean result = JNI_FALSE;

    if (!algorithmName) {
        throwNullPointerException(env, "algorithmName is null");
        goto cleanup;
    }
    algoUtf = (*env)->GetStringUTFChars(env, algorithmName, 0);

    uiAlgID = SDF_GetDigestAlgoId(algoUtf);
    if (uiAlgID == SDF_INVALID_VALUE) {
        throwSDFRuntimeException(env, "UnSupport digest algorithm");
        goto cleanup;
    }

    if ((rv = SDF_HW_MemoryCalloc(hSessionHandle, uiType, &HASH_CONTEXT)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    if ((rv = SDF_HW_HashInit(hSessionHandle, uiAlgID, uiPublicKey, uiPBKLen,
            pucID, uiIDLength, HASH_CONTEXT)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    result = JNI_TRUE;
cleanup:
    if (algoUtf) {
        (*env)->ReleaseStringUTFChars(env, algorithmName, algoUtf);
    }
    if ((!result) && HASH_CONTEXT) {
        SDF_HW_MemoryFree(hSessionHandle, uiType, HASH_CONTEXT);
    }
    return (jlong) HASH_CONTEXT;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFDigestNative
 * Method:    nativeDigestUpdate
 * Signature: (JJ[BII)V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestUpdate(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jlong ctxAddr, jbyteArray inputArr, jint offset, jint inLen) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned char *pucData = NULL;
    unsigned int uiDataLength = inLen;
    void *HASH_CONTEXT = (void *) ctxAddr;

    SGD_RV rv;

    if (!(pucData = malloc(uiDataLength))) {
        throwOutOfMemoryError(env, "malloc pucData failed");
        goto cleanup;
    }

    (*env)->GetByteArrayRegion(env, inputArr, offset, uiDataLength, pucData);

    if ((rv = SDF_HW_HashUpdate(hSessionHandle, pucData, uiDataLength, HASH_CONTEXT) != SDR_OK)) {
        throwSDFException(env, rv);
        goto cleanup;
    }

cleanup:
    if (pucData) {
        free(pucData);
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFDigestNative
 * Method:    nativeDigestFinal
 * Signature: (JJI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestFinal(
        JNIEnv *env, jclass cls, jlong sessionHandleAddr, jlong ctxAddr, jint digestLen) {
    SGD_HANDLE sessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned char *pucHash;
    unsigned int puiHashLength = 0;
    void *HASH_CONTEXT = (void *) ctxAddr;

    jbyteArray result = NULL;

    SGD_RV rv;

    if (!(pucHash = malloc(digestLen))) {
        throwOutOfMemoryError(env, "malloc pucHash failed");
        goto cleanup;
    }

    if ((rv = SDF_HW_HashFinal(sessionHandle, pucHash, &puiHashLength, HASH_CONTEXT)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    result = (*env)->NewByteArray(env, digestLen);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize) puiHashLength, (jbyte *) pucHash);
cleanup:
    if (pucHash) {
        free(pucHash);
    }
    return result;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFDigestNative
 * Method:    nativeDigestCtxFree
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestCtxFree(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jlong ctxAddr) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned int uiType = SDF_CTX_TYPE_DIGEST;
    void *uiHandle = (void *) ctxAddr;
    SGD_RV rv;
    if ((rv = SDF_HW_MemoryFree(hSessionHandle, uiType, uiHandle)) != SDR_OK) {
        throwSDFException(env, rv);
        return;
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFDigestNative
 * Method:    nativeDigestCtxClone
 * Signature: (JJ)V
 */
JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestCtxClone
        (JNIEnv *env, jclass cls, jlong sessionHandleAddr, jlong ctxAddr) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned int uiType = SDF_CTX_TYPE_DIGEST;
    void *uiSrcHandle = (void *) ctxAddr;
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