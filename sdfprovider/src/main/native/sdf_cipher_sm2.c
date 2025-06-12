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

#include "org_openeuler_sdf_wrapper_SDFSM2CipherNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"
#include <stdlib.h>

JNIEXPORT jobject JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2CipherNative_nativeSM2Encrypt(JNIEnv *env, jclass cls,
        jobjectArray pubKeyArr, jbyteArray pubDataArr) {
    unsigned int keyType = DATA_KEY_SM2;
    unsigned char *publicKey = NULL;
    unsigned int pubKeyLen = 0;
    jbyte *data = NULL;
    unsigned int dataLen = 0;
    unsigned char *encData = NULL;
    unsigned int encDataLen = 0;

    jbyteArray params = NULL;

    SGD_RV rv;

    // public key
    publicKey = SDF_CreateSM2PublicKey(env, pubKeyArr, &pubKeyLen);
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    // data
    data = (*env)->GetByteArrayElements(env, pubDataArr, 0);
    dataLen = (*env)->GetArrayLength(env, pubDataArr);

    // malloc enc data memory
    encDataLen = sizeof(SM2Cipher) + dataLen;
    if ((encData = malloc(encDataLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc encData failed");
        goto cleanup;
    }

    // encrypt
    if ((rv = CDM_AsymEncrypt(keyType, publicKey, pubKeyLen,
            data, dataLen, encData, &encDataLen)) != SDR_OK) {
        throwSDFException(env, rv,"CDM_AsymEncrypt");
        goto cleanup;
    }

    SM2Cipher *sm2Cipher = (SM2Cipher *) encData;
    params = SDF_SM2CipherToObjectArray(env, sm2Cipher);

cleanup:
    SDF_FreeSM2PublicKey(publicKey);
    if (data != NULL) {
        (*env)->ReleaseByteArrayElements(env, pubDataArr, data, 0);
    }
    if (encData != NULL) {
        free(encData);
    }
    return params;
}

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2CipherNative_nativeSM2Decrypt(JNIEnv *env, jclass cls,
        jbyteArray priKeyArr, jobjectArray cipherParams) {
    unsigned int keType = DATA_KEY_SM2;
    void *keyHandle = NULL;
    unsigned char *encData = NULL;
    unsigned int encDataLen;
    jbyte *data = NULL;
    unsigned int dataLen;
    jbyteArray pucDataArray = NULL;
    SGD_RV rv;

    // keyHandle
    keyHandle = SDF_CreateSM2PriKeyHandle(env, priKeyArr);
    SM2Cipher *sm2Cipher = SDF_ObjectArrayToSM2Cipher(env, cipherParams, &encDataLen);

    // encData
    encData = (unsigned char *) sm2Cipher;
    if (encData == NULL) {
        goto cleanup;
    }

    dataLen = sm2Cipher->L;
    if ((data = malloc(dataLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc data failed");
        goto cleanup;
    }

    // decrypt
    if ((rv = CDM_AsymDecrypt(keType, keyHandle, encData, encDataLen, data,
            &dataLen) != SDR_OK)) {
        throwSDFException(env, rv, "CDM_AsymDecrypt");
        goto cleanup;
    }

    pucDataArray = (*env)->NewByteArray(env, dataLen);
    (*env)->SetByteArrayRegion(env, pucDataArray, 0, dataLen, data);

cleanup:
    if (keyHandle) {
        CDM_DestroyKeyHandle(keyHandle);
    }
    if (encData) {
        free(encData);
    }
    if (data) {
        free(data);
    }
    return pucDataArray;
}
