/*
 * Copyright (c) 2025, Huawei Technologies Co., Ltd. All rights reserved.
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

#include "org_openeuler_sdf_wrapper_SDFSM9CipherNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"
#include <stdlib.h>

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFSM9CipherNative_nativeSM9Encrypt(JNIEnv *env, jclass cls,
    jbyteArray pubKeyArr, jbyteArray inputArr, jint encMode, jbyteArray hIdArr, jbyteArray userIdArr, jbyteArray pairGArr) {
    unsigned char *publicKey = NULL;
    unsigned int pubKeyLen = 0;
    unsigned char *input = NULL;
    unsigned int inputLen = 0;
    unsigned char *hId = NULL;
    unsigned char *userId = NULL;
    unsigned int userIdLen = 0;
    unsigned char *pairG = NULL;
    unsigned int pairGLen = 0;

    unsigned char *encData = NULL;
    unsigned int encDataLen = 0;

    jbyteArray params = NULL;
    SGD_RV rv;

    // enc public key
    publicKey = (*env)->GetByteArrayElements(env, pubKeyArr, NULL);
    pubKeyLen = (*env)->GetArrayLength(env, pubKeyArr);
    // input data
    inputLen = (*env)->GetArrayLength(env, inputArr);
    //input = (*env)->GetByteArrayElements(env, inputArr, NULL);
    input = calloc(inputLen + 1, 1);
    (*env)->GetByteArrayRegion(env, inputArr, 0, inputLen, input);

    // hid and userId
    hId = (*env)->GetByteArrayElements(env, hIdArr, NULL);
    if (hId == NULL || (*env)->GetArrayLength(env, hIdArr) != 1) {
        throwSDFException(env, SDR_PARAM_ERR, "hId must be one byte");
        goto cleanup;
    }
    userId = (*env)->GetByteArrayElements(env, userIdArr, NULL);
    userIdLen = (*env)->GetArrayLength(env, userIdArr);

    pairG = (*env)->GetByteArrayElements(env, pairGArr, NULL);
    pairGLen = (*env)->GetArrayLength(env, pairGArr);

    encDataLen = inputLen + 200;
    // malloc enc data memory
    if ((encData = malloc(encDataLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc encData failed");
        goto cleanup;
    }

    // encrypt
    if ((rv = CDM_AsymEncryptSM9(encMode, hId[0], userId, userIdLen, publicKey, pubKeyLen, pairG, pairGLen,
                                 input, inputLen, encData, &encDataLen)) != SDR_OK) {
        throwSDFException(env, rv,"CDM_AsymEncryptSM9");
        goto cleanup;
    }

    params = (*env)->NewByteArray(env, encDataLen);
    if (params == NULL) {
        SDF_LOG_ERROR("nativeSM9Encrypt failed to allocate encData");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, params, 0, encDataLen, (jbyte *) encData);

cleanup:
    if (publicKey != NULL) {
        (*env)->ReleaseByteArrayElements(env, pubKeyArr, publicKey, 0);
    }
    if (input != NULL) {
        free(input);
        //(*env)->ReleaseByteArrayElements(env, inputArr, input, 0);
    }
    if (hId != NULL) {
        (*env)->ReleaseByteArrayElements(env, hIdArr, hId, 0);
    }
    if (userId != NULL) {
        (*env)->ReleaseByteArrayElements(env, userIdArr, userId, 0);
    }
    if (pairG != NULL) {
        (*env)->ReleaseByteArrayElements(env, pairGArr, pairG, 0);
    }
    if (encData != NULL) {
        free(encData);
    }
    return params;
}

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFSM9CipherNative_nativeSM9Decrypt(JNIEnv *env, jclass cls,
        jbyteArray priKeyArr, jbyteArray cipherArr, jint encMode, jbyteArray userIdArr, jbyteArray pairGArr) {
    void *keyHandle = NULL;
    unsigned char *cipher = NULL;
    unsigned int cipherLen = 0;
    unsigned char *userId = NULL;
    unsigned int userIdLen = 0;
    unsigned char *pairG = NULL;
    unsigned int pairGLen = 0;
    unsigned char *decData = NULL;
    unsigned int decDataLen = 1024;
    jbyteArray params = NULL;
    SGD_RV rv;

    // keyHandle
    keyHandle = SDF_CreateSM9PriKeyHandle(env, priKeyArr);

    cipher = (*env)->GetByteArrayElements(env, cipherArr, NULL);
    cipherLen = (*env)->GetArrayLength(env, cipherArr);

    userId = (*env)->GetByteArrayElements(env, userIdArr, NULL);
    userIdLen = (*env)->GetArrayLength(env, userIdArr);

    pairG = (*env)->GetByteArrayElements(env, pairGArr, NULL);
    pairGLen = (*env)->GetArrayLength(env, pairGArr);

    if ((decData = malloc(decDataLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc decData failed");
        goto cleanup;
    }
    // get decrypt data len
    if ((rv = CDM_AsymDecryptSM9(encMode, userId, userIdLen, keyHandle, cipher, cipherLen,
                                 decData, &decDataLen) != SDR_OK)) {
        throwSDFException(env, rv, "CDM_AsymDecryptSM9");
        goto cleanup;
    }

    params = (*env)->NewByteArray(env, decDataLen);
    if (params == NULL) {
        SDF_LOG_ERROR("nativeSM9Decrypt failed to allocate decData");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, params, 0, decDataLen, (jbyte *) decData);

cleanup:
    if (keyHandle) {
        CDM_DestroyKeyHandle(keyHandle);
    }
    if (decData) {
        free(decData);
    }
    if (cipher != NULL) {
        (*env)->ReleaseByteArrayElements(env, cipherArr, cipher, 0);
    }
    if (userId != NULL) {
        (*env)->ReleaseByteArrayElements(env, userIdArr, userId, 0);
    }
    if (pairG != NULL) {
        (*env)->ReleaseByteArrayElements(env, pairGArr, pairG, 0);
    }
    return params;
}
