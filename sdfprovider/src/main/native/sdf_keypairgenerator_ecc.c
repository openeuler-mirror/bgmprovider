/*
 * Copyright (c) 2026, Huawei Technologies Co., Ltd. All rights reserved.
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
 * Please visit https://gitcode.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */
#include "cryptocard/crypto_sdk_pf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFECCKeyPairGeneratorNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"

// ECC Key index.
enum SDF_ECCKeyIndex {
    SDF_ECC_PBK_X_IDX = 0,
    SDF_ECC_PBK_Y_IDX = 1,
    SDF_ECC_PRK_S_IDX = 2,
    SDF_ECC_KEY_PARAMS_LEN = 3
};

// Convert KeyPair in sdf to byte[][] in java
jobjectArray SDF_NewECCKeyParams(JNIEnv *env,char *pubKey, char *cipherPriKey, unsigned int cipherPriKeyLen) {
    jobjectArray params = NULL;
    jbyteArray pbkXArr = NULL;
    unsigned char *x = NULL;
    unsigned int xLen = ECC_KEY_BUF_LEN;
    jbyteArray pbkYArr = NULL;
    unsigned char *y = NULL;
    unsigned int yLen = ECC_KEY_BUF_LEN;
    unsigned int bits = 0;
    jbyteArray prkSArr = NULL;
    SGD_RV rv;

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    int arrayLen = SDF_ECC_KEY_PARAMS_LEN;
    params = (*env)->NewObjectArray(env, arrayLen, byteArrayClass, NULL);
    if (params == NULL) {
        SDF_LOG_ERROR("SDF_NewECCKeyParams failed to allocate params");
        goto cleanup;
    }

    if ((x = malloc(xLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc x failed");
        goto cleanup;
    }
    if ((y = malloc(yLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc x failed");
        goto cleanup;
    }

// TODO 需要SDK提供解析公私钥的接口
//    if ((rv = CDM_GetECCPubKeyElements(pubKey, x, &xLen, y, &yLen, &bits)) != SDR_OK) {
//        throwSDFException(env, rv, "CDM_GetECCPubKeyElements");
//        goto cleanup;
//    }

    // set public key x-coordinate
    pbkXArr = (*env)->NewByteArray(env, xLen);
    if (pbkXArr == NULL) {
        SDF_LOG_ERROR("SDF_NewECCKeyParams failed to allocate pbkXArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, pbkXArr, 0, xLen, (jbyte *) x);
    (*env)->SetObjectArrayElement(env, params, SDF_ECC_PBK_X_IDX, pbkXArr);

    // set public key y-coordinate
    pbkYArr = (*env)->NewByteArray(env, yLen);
    if (pbkYArr == NULL) {
        SDF_LOG_ERROR("SDF_NewECCKeyParams failed to allocate pbkYArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, pbkYArr, 0, yLen, (jbyte *) y);
    (*env)->SetObjectArrayElement(env, params, SDF_ECC_PBK_Y_IDX, pbkYArr);

    // set private key s
    prkSArr = (*env)->NewByteArray(env, cipherPriKeyLen);
    if (prkSArr == NULL) {
        SDF_LOG_ERROR("SDF_NewECCKeyParams failed to allocate prkSArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, prkSArr, 0, cipherPriKeyLen, cipherPriKey);
    (*env)->SetObjectArrayElement(env, params, SDF_ECC_PRK_S_IDX, prkSArr);

cleanup:
    if (byteArrayClass != NULL) {
        (*env)->DeleteLocalRef(env, byteArrayClass);
    }
    if (pbkXArr != NULL) {
        (*env)->DeleteLocalRef(env, pbkXArr);
    }
    if (pbkYArr != NULL) {
        (*env)->DeleteLocalRef(env, pbkYArr);
    }
    if (prkSArr != NULL) {
        (*env)->DeleteLocalRef(env, prkSArr);
    }
    if (x != NULL) {
        free(x);
    }
    if (y != NULL) {
        free(y);
    }
    return params;
}

JNIEXPORT jobjectArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFECCKeyPairGeneratorNative_nativeGenerateKeyPair(JNIEnv *env, jclass cls, jint keySize,
    jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId, jbyteArray pin) {
    unsigned int algId = ALG_SM4;
    unsigned int ivLen = 16;
    unsigned char iv[ivLen];
    void *dekParams = NULL;
    unsigned int outKeyType = DATA_KEY_ECC;
    unsigned int outKeyLen = keySize;
    char *pubKey = NULL;
    unsigned int pubKeyLen = 0;
    char *cipherPriKey = NULL;
    unsigned int cipherPriKeyLen = 0;
    jobjectArray keyParams = NULL;
    SGD_RV rv;

    if (!(dekParams = SDF_CreateDEKParams(env, kekId, regionId, cdpId, pin))) {
        goto cleanup;
    }

    if ((rv = CDM_GenRandom(ivLen, iv)) != SDR_OK) {
        throwSDFException(env, rv, "ECC GenerateKeyPair CDM_GenRandom");
        goto cleanup;
    }
    // compute private key len and public key len
    if ((rv = CDM_CreateDataKeyPairsWithoutPlaintext(algId, iv, ivLen, dekParams, outKeyType, outKeyLen,
            pubKey, &pubKeyLen, cipherPriKey, &cipherPriKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "ECC GenerateKeyPair  CDM_CreateDataKeyPairsWithoutPlaintext");
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

    // generate key pair
    if ((rv = CDM_CreateDataKeyPairsWithoutPlaintext(algId, iv, ivLen, dekParams, outKeyType, outKeyLen,
            pubKey, &pubKeyLen, cipherPriKey, &cipherPriKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDataKeyPairsWithoutPlaintext");
        goto cleanup;
    }

    keyParams = SDF_NewECCKeyParams(env, pubKey, cipherPriKey, cipherPriKeyLen);
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
    return keyParams;
}