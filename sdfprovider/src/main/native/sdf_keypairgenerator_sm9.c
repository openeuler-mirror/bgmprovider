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
#include "cryptocard/crypto_sdk_pf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFSM9KeyPairGeneratorNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"

// Convert KeyPair in sdf to byte[][] in java
jobjectArray SDF_NewSM9KeyParams(JNIEnv *env,char *pubKey, unsigned int pubKeyLen,
        char *cipherPriKey, unsigned int cipherPriKeyLen, char *pairG, unsigned int pairGLen) {
    jobjectArray params = NULL;
    jbyteArray pubKeyArr = NULL;
    jbyteArray priKeyArr = NULL;
    jbyteArray pairGArr = NULL;
    SGD_RV rv;

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    int arrayLen = 3;
    params = (*env)->NewObjectArray(env, arrayLen, byteArrayClass, NULL);
    if (params == NULL) {
        SDF_LOG_ERROR("SDF_NewSM2KeyParams failed to allocate params");
        goto cleanup;
    }

    if ((pubKeyArr = malloc(pubKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pubKey failed");
        goto cleanup;
    }
    if ((priKeyArr = malloc(cipherPriKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc cipherPriKey failed");
        goto cleanup;
    }
    if ((pairGArr = malloc(pairGLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pairG failed");
        goto cleanup;
    }

    // set public key x-coordinate
    pubKeyArr = (*env)->NewByteArray(env, pubKeyLen);
    if (pubKeyArr == NULL) {
        SDF_LOG_ERROR("SDF_NewSM2KeyParams failed to allocate pubKeyArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, pubKeyArr, 0, pubKeyLen, (jbyte *) pubKey);
    (*env)->SetObjectArrayElement(env, params, 0, pubKeyArr);

    // set public key y-coordinate
    priKeyArr = (*env)->NewByteArray(env, cipherPriKeyLen);
    if (priKeyArr == NULL) {
        SDF_LOG_ERROR("SDF_NewSM2KeyParams failed to allocate priKeyArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, priKeyArr, 0, cipherPriKeyLen, (jbyte *) cipherPriKey);
    (*env)->SetObjectArrayElement(env, params, 1, priKeyArr);

    // set private key s
    pairGArr = (*env)->NewByteArray(env, pairGLen);
    if (pairGArr == NULL) {
        SDF_LOG_ERROR("SDF_NewSM2KeyParams failed to allocate pairGArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, pairGArr, 0, pairGLen, (jbyte *) pairG);
    (*env)->SetObjectArrayElement(env, params, 2, pairGArr);

cleanup:
    if (byteArrayClass != NULL) {
        (*env)->DeleteLocalRef(env, byteArrayClass);
    }
    if (pubKeyArr != NULL) {
        (*env)->DeleteLocalRef(env, pubKeyArr);
    }
    if (priKeyArr != NULL) {
        (*env)->DeleteLocalRef(env, priKeyArr);
    }
    if (pairGArr != NULL) {
        (*env)->DeleteLocalRef(env, pairGArr);
    }
    return params;
}

JNIEXPORT jobjectArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFSM9KeyPairGeneratorNative_nativeGenerateKeyPair(JNIEnv *env, jclass cls, jint keyType,
    jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId, jbyteArray pin) {
    unsigned int algId = ALG_SM4;
    void *dekParams = NULL;
    unsigned int outKeyType = keyType;
    char *pubKey = NULL;
    unsigned int pubKeyLen = 0;
    char *cipherPriKey = NULL;
    unsigned int cipherPriKeyLen = 0;
    char *pairG = NULL;
    unsigned int pairGLen = 0;
    jobjectArray keyParams = NULL;
    SGD_RV rv;

    if (!(dekParams = SDF_CreateDEKParams(env, kekId, regionId, cdpId, pin))) {
        goto cleanup;
    }

    // compute private key len and public key len
    if ((rv = CDM_CreateDataKeyPairsWithoutPlaintextSM9Master(algId, dekParams, outKeyType, pubKey, &pubKeyLen,
                    cipherPriKey, &cipherPriKeyLen, pairG, &pairGLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDataKeyPairsWithoutPlaintext");
        goto cleanup;
    }

    // public key
    if ((pubKey = malloc(pubKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pubKey failed");
        goto cleanup;
    }

    // private key
    if ((cipherPriKey = malloc(cipherPriKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc cipherPriKey failed");
        goto cleanup;
    }

    // pairG
    if ((pairG = malloc(pairGLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pairG failed");
        goto cleanup;
    }

    // generate key pair
    if ((rv = CDM_CreateDataKeyPairsWithoutPlaintextSM9Master(algId, dekParams, outKeyType, pubKey, &pubKeyLen,
                      cipherPriKey, &cipherPriKeyLen, pairG, &pairGLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDataKeyPairsWithoutPlaintext");
        goto cleanup;
    }

    keyParams = SDF_NewSM9KeyParams(env, pubKey, pubKeyLen, cipherPriKey, cipherPriKeyLen, pairG, pairGLen);
    if (keyParams == NULL) {
        throwSDFRuntimeException(env, "SDF_NewKeyParams failed");
        goto cleanup;
    }

cleanup:
    SDF_FreeDEKParams(env, dekParams);
    if (pubKey != NULL) {
        free(pubKey);
    }
    if (cipherPriKey != NULL) {
        free(cipherPriKey);
    }
    if (pairG != NULL) {
        free(pairG);
    }
    return keyParams;
}

JNIEXPORT jbyteArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFSM9KeyPairGeneratorNative_nativeCreateUserPriKey(JNIEnv *env, jclass cls, jint keyType,
    jbyteArray priKeyArr, jbyteArray hIdArr, jbyteArray userIdArr) {
    jbyteArray params = NULL;
    unsigned int outKeyType = keyType;
    void* priKeyHandle;
    unsigned char* hId = NULL;
    unsigned char* userId = NULL;
    unsigned int userIdLen = 0;
    char *signUserPriKey = NULL;
    unsigned int signUserPriKeyLen = 0;
    SGD_RV rv;

    // private key handle
    priKeyHandle = SDF_CreateSM9PriKeyHandle(env, priKeyArr);
    userIdLen = (*env)->GetArrayLength(env, userIdArr);
    userId = (*env)->GetByteArrayElements(env, userIdArr, NULL);
    hId = (*env)->GetByteArrayElements(env, hIdArr, NULL);

    if ((rv = CDM_CreateDataKeyPairsWithoutPlaintextSM9User(outKeyType, priKeyHandle, hId[0], userId, userIdLen,
                        signUserPriKey, &signUserPriKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDataKeyPairsWithoutPlaintextSM9User");
        goto cleanup;
    }

    // public key
    if ((signUserPriKey = malloc(signUserPriKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc signUserPriKey failed");
        goto cleanup;
    }

    if ((rv = CDM_CreateDataKeyPairsWithoutPlaintextSM9User(outKeyType, priKeyHandle, hId[0], userId, userIdLen,
                            signUserPriKey, &signUserPriKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDataKeyPairsWithoutPlaintextSM9User");
        goto cleanup;
    }

    // set public key x-coordinate
    params = (*env)->NewByteArray(env, signUserPriKeyLen);
    if (params == NULL) {
        SDF_LOG_ERROR("SDF_NewPubKeyParams failed to allocate signUserPriKey");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, params, 0, signUserPriKeyLen, (jbyte *) signUserPriKey);

cleanup:
    if (priKeyHandle != NULL) {
        CDM_DestroyKeyHandle(priKeyHandle);
    }
    if (signUserPriKey != NULL) {
        free(signUserPriKey);
    }
    if (hId != NULL) {
        free(hId);
    }
    if (userId != NULL) {
        free(userId);
    }
    return params;
}