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

#include "org_openeuler_sdf_wrapper_SDFSM9SignatureNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFSM9SignatureNative_nativeSM9Sign(
        JNIEnv *env, jclass clz, jbyteArray pubKeyArr, jbyteArray priKeyArr, jbyteArray dataArr, jbyteArray pairGArr)
{
    void *keyHandle = NULL;
    unsigned char *pubKey = NULL;
    unsigned int pubKeyLen;
    unsigned char *pairG = NULL;
    unsigned int pairGLen;
    unsigned char *data = NULL;
    unsigned int dataLen;

    unsigned char *signature = NULL;
    unsigned int signatureLen;
    SGD_RV rv;
    jbyteArray params = NULL;

    // private key
    keyHandle = SDF_CreateSM9PriKeyHandle(env,priKeyArr);

    pubKey = (*env)->GetByteArrayElements(env, pubKeyArr, NULL);
    pubKeyLen = (*env)->GetArrayLength(env, pubKeyArr);
    pairG = (*env)->GetByteArrayElements(env, pairGArr, NULL);
    pairGLen = (*env)->GetArrayLength(env, pairGArr);
    data = (*env)->GetByteArrayElements(env, dataArr, NULL);
    dataLen = (*env)->GetArrayLength(env, dataArr);

    // malloc signature
    if ((signature = malloc(96 * sizeof(char))) == NULL) {
        SDF_LOG_ERROR("malloc signature failed");
        throwOutOfMemoryError(env, "malloc signature failed");
        goto cleanup;
    }
    // sign len
    if ((rv = CDM_AsymSignSM9(keyHandle, pubKey, pubKeyLen,
                              pairG, pairGLen, data, dataLen, signature, &signatureLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_AsymSignSM9");
        goto cleanup;
    }
    printf("signatureLen: %d\n", signatureLen);

//    // malloc signature
//    if ((signature = malloc(signatureLen)) == NULL) {
//        SDF_LOG_ERROR("malloc signature failed");
//        throwOutOfMemoryError(env, "malloc signature failed");
//        goto cleanup;
//    }

    // sign
//    if ((rv = CDM_AsymSignSM9(keyHandle, pubKey, pubKeyLen,
//                              pairG, pairGLen, data, dataLen, signature, &signatureLen)) != SDR_OK) {
//        throwSDFException(env, rv, "CDM_AsymSignSM9");
//        goto cleanup;
//    }

    params = (*env)->NewByteArray(env, signatureLen);
    if (params == NULL) {
        SDF_LOG_ERROR("nativeSM9Sign failed to allocate encData");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, params, 0, signatureLen, (jbyte *) signature);

cleanup:
    if (keyHandle != NULL) {
        CDM_DestroyKeyHandle(keyHandle);
    }
    if (pubKey != NULL) {
        (*env)->ReleaseByteArrayElements(env, pubKeyArr, pubKey, 0);
    }
    if (pairG != NULL) {
        (*env)->ReleaseByteArrayElements(env, pairGArr, pairG, 0);
    }
    if (data != NULL) {
        (*env)->ReleaseByteArrayElements(env, dataArr, data, 0);
    }
    if (signature != NULL) {
        free(signature);
    }

    return params;
}


JNIEXPORT jboolean JNICALL Java_org_openeuler_sdf_wrapper_SDFSM9SignatureNative_nativeSM9Verify(
        JNIEnv *env, jclass clz, jbyteArray pubKeyArr, jbyteArray signArr, jbyteArray dataArr,
        jbyteArray pairGArr, jbyteArray hIdArr, jbyteArray userIdArr)
{
    unsigned char *pubKey = NULL;
    unsigned int pubKeyLen = 0;
    unsigned char *data = NULL;
    unsigned int dataLen = 0;
    unsigned char *hId = NULL;
    unsigned char *userId = NULL;
    unsigned int userIdLen = 0;
    unsigned char *pairG = NULL;
    unsigned int pairGLen = 0;
    unsigned char *signature = NULL;
    unsigned int signatureLen = 0;

    SGD_RV rv;
    jboolean result = JNI_FALSE;

    // enc public key
    pubKey = (*env)->GetByteArrayElements(env, pubKeyArr, NULL);
    pubKeyLen = (*env)->GetArrayLength(env, pubKeyArr);
    signature = (*env)->GetByteArrayElements(env, signArr, NULL);
    signatureLen = (*env)->GetArrayLength(env, signArr);
    // input data
    data = (*env)->GetByteArrayElements(env, dataArr, NULL);
    dataLen = (*env)->GetArrayLength(env, dataArr);
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

    if ((rv = CDM_AsymVerifySM9(hId[0], userId, userIdLen, pubKey, pubKeyLen,
                                pairG, pairGLen, data, dataLen, signature, signatureLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_AsymVerify");
        goto cleanup;
    }

    result = JNI_TRUE;
cleanup:
    if (pubKey != NULL) {
        (*env)->ReleaseByteArrayElements(env, pubKeyArr, pubKey, 0);
    }
    if (data != NULL) {
        (*env)->ReleaseByteArrayElements(env, dataArr, data, 0);
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
    if (signature != NULL) {
        (*env)->ReleaseByteArrayElements(env, signArr, signature, 0);
    }
    return result;
}
