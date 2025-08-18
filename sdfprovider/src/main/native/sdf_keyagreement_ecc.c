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
#include "cryptocard/crypto_sdk_pf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

JNIEXPORT jbyteArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative_decodeECCPreMasterKey(JNIEnv *env, jclass cls,
        jbyteArray priKeyArr, jobjectArray pubEncCmkParams) {
    int keyType = DATA_KEY_SM2;
    void *priKeyHandle = NULL;
    unsigned char *encData = NULL;
    unsigned int encDataLen;
    unsigned char *cipherKey = NULL;
    unsigned int cipherKeyLen = 0;
    jbyteArray keyArr = NULL;
    SGD_RV rv;

    priKeyHandle = SDF_CreateSM2PriKeyHandle(env, priKeyArr, NULL);
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    encData = (unsigned char *) SDF_ObjectArrayToSM2Cipher(env, pubEncCmkParams, &encDataLen);

    // compute cipherKeyLen
    if ((rv = CDM_PreMasterKeyExchange(keyType, priKeyHandle, encData, encDataLen, cipherKey, &cipherKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_PreMasterKeyExchange");
        goto cleanup;
    }

    if (!(cipherKey = malloc(cipherKeyLen))) {
        throwOutOfMemoryError(env, "malloc cipherKey failed");
        goto cleanup;
    }

    if ((rv = CDM_PreMasterKeyExchange(keyType, priKeyHandle, encData, encDataLen, cipherKey, &cipherKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_PreMasterKeyExchange");
        goto cleanup;
    }
    // new keyArr
    keyArr = (*env)->NewByteArray(env, cipherKeyLen);
    (*env)->SetByteArrayRegion(env, keyArr, 0, cipherKeyLen, (jbyte *) cipherKey);
cleanup:
    if (cipherKey) {
        free(cipherKey);
    }
    if (encData) {
        free(encData);
    }
    SDF_FreeSM2PriKeyHandle(priKeyHandle);
    return keyArr;
}


JNIEXPORT jobjectArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative_generateECCPreMasterKey(JNIEnv *env, jclass cls,
        jbyteArray kekIdArr, jbyteArray regionIdArr, jbyteArray cdpIdArr, jbyteArray pinArr,
        jobjectArray pubKeyArr, jint clientVersion) {
    int algId = ALG_SM4;
    unsigned int ivLen = 16;
    unsigned char iv[ivLen];
    unsigned int keyType = DATA_KEY_SM2;
    void *dekParams = NULL;
    unsigned char *pubKey = NULL;
    unsigned int pubKeyLen = 0;
    char *kekEncCmk = NULL;
    unsigned int kekEncCmkLen = 0;
    char *pubEncCmk = NULL;
    unsigned int pubEncCmkLen = 0;

    jclass objectClass = NULL;
    jobjectArray result = NULL;

    SGD_RV rv;

    // iv
    if ((rv = CDM_GenRandom(ivLen, iv)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_GenRandom");
        goto cleanup;
    }

    // DEKParams
    if (!(dekParams = SDF_CreateDEKParams(env, kekIdArr, regionIdArr, cdpIdArr, pinArr))) {
        goto cleanup;
    }

    // public key
    pubKey = SDF_CreateSM2PublicKey(env, pubKeyArr, &pubKeyLen);

    // compute kekEncCmkLen, pubEncCmkLen
    if ((rv = CDM_CreatePreMasterKey(algId, iv, ivLen, keyType, dekParams, clientVersion, pubKey, pubKeyLen,
            kekEncCmk, &kekEncCmkLen, pubEncCmk, &pubEncCmkLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreatePreMasterKey");
        goto cleanup;
    }

    if (!(kekEncCmk = malloc(kekEncCmkLen))) {
        throwOutOfMemoryError(env, "malloc kekEncCmk failed");
        goto cleanup;
    }

    if (!(pubEncCmk = malloc(pubEncCmkLen))) {
        throwOutOfMemoryError(env, "malloc pubEncCmk failed");
        goto cleanup;
    }

    // get kekEncCmk and pubEncCmk
    if ((rv = CDM_CreatePreMasterKey(algId, iv, ivLen, keyType, dekParams, clientVersion, pubKey, pubKeyLen,
            kekEncCmk, &kekEncCmkLen, pubEncCmk, &pubEncCmkLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreatePreMasterKey");
        goto cleanup;
    }

    jbyteArray kekEncCmkArr = (*env)->NewByteArray(env, kekEncCmkLen);
    (*env)->SetByteArrayRegion(env, kekEncCmkArr, 0, kekEncCmkLen, kekEncCmk);
    jbyteArray pubEncCmkParams = SDF_SM2CipherToObjectArray(env, (SM2Cipher *) pubEncCmk);
    objectClass = (*env)->FindClass(env, "java/lang/Object");
    result = (*env)->NewObjectArray(env, 2, objectClass, NULL);
    (*env)->SetObjectArrayElement(env, result, 0, kekEncCmkArr);
    (*env)->SetObjectArrayElement(env, result, 1, pubEncCmkParams);

cleanup:
    SDF_FreeDEKParams(env, dekParams);
    SDF_FreeSM2PublicKey(pubKey);
    if (objectClass) {
        (*env)->DeleteLocalRef(env, objectClass);
    }
    return result;
}