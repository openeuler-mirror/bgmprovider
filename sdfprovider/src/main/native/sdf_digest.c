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

#include "org_openeuler_sdf_wrapper_SDFDigestNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestInit(JNIEnv *env, jclass cls,
        jstring algorithmName) {
    unsigned int type = CTX_TYPE_HASH;
    unsigned int algId;
    unsigned char *pubKey = NULL;
    unsigned int pubKeyLen = 0;
    unsigned char *id = NULL;
    unsigned int idLen = 0;
    void *hashContext = NULL;
    const char *algoUtf = NULL;
    SGD_RV rv;

    jboolean result = JNI_FALSE;
    algoUtf = (*env)->GetStringUTFChars(env, algorithmName, 0);
    algId = SDF_GetDigestAlgoId(algoUtf);
    if (algId == SDF_INVALID_VALUE) {
        throwSDFRuntimeException(env, "UnSupport digest algorithm");
        goto cleanup;
    }

    if ((rv = CDM_MemoryCalloc(type, &hashContext)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryCalloc");
        goto cleanup;
    }

    if ((rv = CDM_HashInit(algId, pubKey, pubKeyLen,
            id, idLen, hashContext)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_HashInit");
        goto cleanup;
    }
    result = JNI_TRUE;

cleanup:
    if (algoUtf) {
        (*env)->ReleaseStringUTFChars(env, algorithmName, algoUtf);
    }
    if ((!result) && hashContext) {
        CDM_MemoryFree(type, hashContext);
    }
    return (jlong) hashContext;
}

JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestUpdate(JNIEnv *env, jclass cls,
        jlong ctxAddr, jbyteArray inputArr, jint offset, jint inLen) {
    unsigned char *data = NULL;
    unsigned int dataLen = inLen;
    void *hashContext = (void *) ctxAddr;
    SGD_RV rv;

    if (!(data = malloc(dataLen))) {
        throwOutOfMemoryError(env, "malloc data failed");
        goto cleanup;
    }

    (*env)->GetByteArrayRegion(env, inputArr, offset, dataLen, data);

    if ((rv = CDM_HashUpdate(data, dataLen, hashContext) != SDR_OK)) {
        throwSDFException(env, rv, "CDM_HashUpdate");
        goto cleanup;
    }

cleanup:
    if (data) {
        free(data);
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestFinal(
        JNIEnv *env, jclass cls, jlong ctxAddr, jint digestLen) {
    unsigned char *hash;
    unsigned int hashLen = digestLen;
    void *hashContext = (void *) ctxAddr;
    jbyteArray hashArr = NULL;
    SGD_RV rv;

    if (!(hash = malloc(digestLen))) {
        throwOutOfMemoryError(env, "malloc hash failed");
        goto cleanup;
    }

    if ((rv = CDM_HashFinal(hashContext, hash, &hashLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_HashFinal");
        goto cleanup;
    }

    hashArr = (*env)->NewByteArray(env, digestLen);
    (*env)->SetByteArrayRegion(env, hashArr, 0, (jsize) hashLen, (jbyte *) hash);

cleanup:
    if (hash) {
        free(hash);
    }
    return hashArr;
}

JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestCtxFree(JNIEnv *env, jclass cls,
        jlong ctxAddr) {
    unsigned int type = CTX_TYPE_HASH;
    void *hashContext = (void *) ctxAddr;
    SGD_RV rv;

    if ((rv = CDM_MemoryFree(type, hashContext)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryFree");
        return;
    }
}

JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFDigestNative_nativeDigestCtxClone
        (JNIEnv *env, jclass cls, jlong ctxAddr) {
    unsigned int type = CTX_TYPE_HASH;
    void *srcHandle = (void *) ctxAddr;
    void *dstHandle = NULL;
    SGD_RV rv;

    if ((rv = CDM_MemoryCalloc(type, &dstHandle) != SDR_OK)) {
        throwSDFException(env, rv, "CDM_MemoryCalloc");
        goto cleanup;
    }
    if ((rv = CDM_MemoryCopy(type, srcHandle, dstHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryCopy");
        goto cleanup;
    }
    return (jlong) dstHandle;

cleanup:
    return 0;
}