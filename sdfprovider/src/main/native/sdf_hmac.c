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

#include "org_openeuler_sdf_wrapper_SDFHmacNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacInit
        (JNIEnv *env, jclass cls, jbyteArray keyBytes) {
    unsigned char *key = NULL;
    unsigned int keyLen;
    void *keyHandle = NULL;
    unsigned int type = CTX_TYPE_HMAC;
    void *hmacContext = NULL;
    int rv = SDR_UNKNOWERR;

    keyLen = (*env)->GetArrayLength(env, keyBytes);
    if ((key = malloc(keyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc key failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, keyBytes, 0, keyLen, key);

    // import key
    if ((rv = CDM_ImportKeyHandle(key, keyLen, NULL, 0, &keyHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_ImportKeyHandle");
        goto cleanup;
    }

    // new hmacContext
    if ((rv = CDM_MemoryCalloc(type, &hmacContext)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryCalloc");
        goto cleanup;
    }

    // hmac init
    if ((rv = CDM_HMACInit(keyHandle, hmacContext)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_HMACInit");
        goto cleanup;
    }

cleanup:
    if (key != NULL) {
        free(key);
    }
    // keyHandle can be free after CDM_HMACInit
    if (keyHandle != NULL) {
        CDM_DestroyKeyHandle(keyHandle);
    }
    if (rv != SDR_OK && hmacContext != NULL) {
        CDM_MemoryFree(type, hmacContext);
    }
    return (jlong) hmacContext;
}

JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacUpdate
        (JNIEnv *env, jclass cls, jlong ctxAddress, jbyteArray input, jint offset, jint len) {
    void *hmacContext = (void *) ctxAddress;
    unsigned char *data = NULL;
    unsigned int dataLen = len;
    int rv;

    if (!(data = malloc(dataLen))) {
        throwOutOfMemoryError(env, "malloc data failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, input, offset, len, data);

    if ((rv = CDM_HMACUpdate(data, dataLen, hmacContext)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_HMACUpdate");
        goto cleanup;
    }

cleanup:
    if (data != NULL) {
        free(data);
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacFinal
        (JNIEnv *env, jclass cls, jlong ctxAddress, jint macLen) {
    void *hmacContext = (void *) ctxAddress;
    unsigned char *hmac = NULL;
    unsigned int hmacLen = macLen;
    jbyteArray hmacArr = NULL;
    int rv;

    if (!(hmac = malloc(macLen))) {
        throwOutOfMemoryError(env, "malloc hmac failed");
        goto cleanup;
    }

    if ((rv = CDM_HMACFinal(hmacContext, hmac, &hmacLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_HMACFinal");
        goto cleanup;
    }

    hmacArr = (*env)->NewByteArray(env, hmacLen);
    (*env)->SetByteArrayRegion(env, hmacArr, 0, hmacLen, hmac);

cleanup:
    if (hmac != NULL) {
        free(hmac);
    }
    return hmacArr;
}


JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacContextFree
        (JNIEnv *env, jclass cls, jlong ctxAddress) {
    unsigned int type = CTX_TYPE_HMAC;
    void *hmacContext = (void *) ctxAddress;
    int rv;

    if (hmacContext == NULL) {
        return;
    }

    if ((rv = CDM_MemoryFree(type, hmacContext)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryFree");
        return;
    }
}

JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFHmacNative_nativeHmacContextClone
        (JNIEnv *env, jclass cls, jlong ctxAddress) {
    unsigned int type = CTX_TYPE_HMAC;
    void *srcHandle = (void *) ctxAddress;
    void *dstHandle = NULL;
    int rv;

    if ((rv = CDM_MemoryCalloc(type, &dstHandle) != SDR_OK)) {
        throwSDFException(env, rv, "CDM_MemoryCalloc");
        goto cleanup;
    }
    if ((rv = CDM_MemoryCopy(type, srcHandle, dstHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryCopy");
        goto cleanup;
    }
    return (jlong) (dstHandle);

cleanup:
    return 0L;
}