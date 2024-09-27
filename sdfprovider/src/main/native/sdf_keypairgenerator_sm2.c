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

#include "org_openeuler_sdf_wrapper_SDFSM2KeyPairGeneratorNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"

// EC Key index.
typedef enum SDF_ECKeyIndex {
    SDF_EC_PBK_X_IDX = 0,
    SDF_EC_PBK_Y_IDX = 1,
    SDF_EC_PRK_S_IDX = 2
} SDF_ECKeyIndex;

// Convert KeyPair in sdf to byte[][] in java
jobjectArray SDF_NewSm2KeyParams(JNIEnv *env, unsigned char *pPublicKey,
        unsigned char *pCipherPriKey, unsigned int PRKLen) {
    jobjectArray params = NULL;
    jbyteArray pbkXArr = NULL;
    jbyteArray pbkYArr = NULL;
    jbyteArray prkSArr = NULL;

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    int arrayLen = SDF_EC_PRK_S_IDX + 1;
    params = (*env)->NewObjectArray(env, arrayLen, byteArrayClass, NULL);
    if (params == NULL) {
        SDF_LOG_ERROR("SDF_NewSm2KeyParams failed to allocate params");
        goto cleanup;
    }

    ECCrefPublicKey_HW *refPublicKey = (ECCrefPublicKey_HW *) pPublicKey;

    // set public key x-coordinate
    pbkXArr = (*env)->NewByteArray(env, ECCref_MAX_LEN_HW);
    if (pbkXArr == NULL) {
        SDF_LOG_ERROR("SDF_NewSm2KeyParams failed to allocate pbkXArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, pbkXArr, 0, ECCref_MAX_LEN_HW, (jbyte *) refPublicKey->x);
    (*env)->SetObjectArrayElement(env, params, SDF_EC_PBK_X_IDX, pbkXArr);

    // set public key y-coordinate
    pbkYArr = (*env)->NewByteArray(env, ECCref_MAX_LEN_HW);
    if (pbkYArr == NULL) {
        SDF_LOG_ERROR("SDF_NewSm2KeyParams failed to allocate pbkYArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, pbkYArr, 0, ECCref_MAX_LEN_HW, (jbyte *) refPublicKey->y);
    (*env)->SetObjectArrayElement(env, params, SDF_EC_PBK_Y_IDX, pbkYArr);

    // set private key s
    prkSArr = (*env)->NewByteArray(env, PRKLen);
    if (prkSArr == NULL) {
        SDF_LOG_ERROR("SDF_NewSm2KeyParams failed to allocate prkSArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, prkSArr, 0, PRKLen, pCipherPriKey);
    (*env)->SetObjectArrayElement(env, params, SDF_EC_PRK_S_IDX, prkSArr);

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
    return params;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSM2KeyPairGeneratorNative
 * Method:    nativeGenerateSM2KeyPair
 * Signature: (J[B[B[B[B)[[B
 */
JNIEXPORT jobjectArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFSM2KeyPairGeneratorNative_nativeGenerateKeyPair(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId, jbyteArray pin) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned int uiAlgID = SGD_SM4_ECB;
    unsigned char *IV = NULL;
    unsigned int IVLen = 0;
    jbyte *uiPIN = NULL;
    unsigned int uiPINLen;
    KEKInfo *uiKEKInfo = NULL;
    unsigned uiKeyType = SDF_ASYMMETRIC_KEY_TYPE_SM2;
    unsigned char *pPublicKey = NULL;
    unsigned int PBKLen;
    unsigned char *pCipherPriKey = NULL;
    unsigned int PRKLen;

    jobjectArray keyParams = NULL;
    SGD_RV rv;

    uiKEKInfo = SDF_NewKEKInfo(env, kekId, regionId, cdpId);
    if (uiKEKInfo == NULL) {
        throwSDFRuntimeException(env, "SDF_NewKEKInfo failed");
        goto cleanup;
    }

    uiPIN = (*env)->GetByteArrayElements(env, pin, NULL);
    uiPINLen = (*env)->GetArrayLength(env, pin);

    PBKLen = SDF_GetAsymmetricPBKLen(uiKeyType);
    if ((pPublicKey = malloc(PBKLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pPublicKey failed");
        goto cleanup;
    }
    memset(pPublicKey, 0, PBKLen);

    PRKLen = SDF_GetAsymmetricPRKLen(uiKeyType);
    if ((pCipherPriKey = malloc(PRKLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pCipherPriKey failed");
        goto cleanup;
    }
    memset(pCipherPriKey, 0, PRKLen);

    if ((rv = SDF_HW_CreateDataKeyPairsWithoutPlaintext(hSessionHandle, uiAlgID, IV, IVLen,
            uiPIN, uiPINLen, uiKEKInfo, uiKeyType,
            pPublicKey, &PBKLen, pCipherPriKey, &PRKLen)) != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    keyParams = SDF_NewSm2KeyParams(env, pPublicKey, pCipherPriKey, PRKLen);
    if (keyParams == NULL) {
        throwSDFRuntimeException(env, "SDF_NewKeyParams failed");
        goto cleanup;
    }

cleanup:
    if (uiPIN != NULL) {
        (*env)->ReleaseByteArrayElements(env, pin, uiPIN, 0);
    }
    if (uiKEKInfo != NULL) {
        SDF_ReleaseKEKInfo(uiKEKInfo);
    }
    if (pPublicKey != NULL) {
        free(pPublicKey);
    }
    if (pCipherPriKey != NULL) {
        free(pCipherPriKey);
    }
    return keyParams;
}

JNIEXPORT jobjectArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFSM2KeyPairGeneratorNative_nativeGeneratePublicKey(JNIEnv *env, jclass cls,
        jbyteArray priKeyArr) {
    jbyteArray pbkXArr = NULL;
    jbyteArray pbkYArr = NULL;
    jclass byteArrayClass = NULL;
    jbyte *pCipherPriKey = NULL;
    jobjectArray params = NULL;

    byteArrayClass = (*env)->FindClass(env, "[B");
    int arrayLen = SDF_EC_PBK_Y_IDX + 1;
    params = (*env)->NewObjectArray(env, arrayLen, byteArrayClass, NULL);
    if (params == NULL) {
        throwOutOfMemoryError(env, "nativeGeneratePublicKey failed to allocate params");
        goto cleanup;
    }

    pCipherPriKey = (*env)->GetByteArrayElements(env, priKeyArr, NULL);
    C_SM2Pairs *sm2Pairs = (C_SM2Pairs *) pCipherPriKey;
    ECCrefPublicKey_HW *refPublicKey = (ECCrefPublicKey_HW *) sm2Pairs->SM2PubKey;

    // set public key x-coordinate
    pbkXArr = (*env)->NewByteArray(env, ECCref_MAX_LEN_HW);
    if (pbkXArr == NULL) {
        throwOutOfMemoryError(env, "nativeGeneratePublicKey failed to allocate pbkXArr");
        goto cleanup;
    }
    jbyte *pbkX = (jbyte *) refPublicKey->x;
    (*env)->SetByteArrayRegion(env, pbkXArr, 0, ECCref_MAX_LEN_HW, pbkX);
    (*env)->SetObjectArrayElement(env, params, SDF_EC_PBK_X_IDX, pbkXArr);

    // set public key y-coordinate
    pbkYArr = (*env)->NewByteArray(env, ECCref_MAX_LEN_HW);
    if (pbkYArr == NULL) {
        throwOutOfMemoryError(env, "nativeGeneratePublicKey failed to allocate pbkYArr");
        goto cleanup;
    }
    jbyte *pbkY = (jbyte *) refPublicKey->y;
    (*env)->SetByteArrayRegion(env, pbkYArr, 0, ECCref_MAX_LEN_HW, pbkY);
    (*env)->SetObjectArrayElement(env, params, SDF_EC_PBK_Y_IDX, pbkYArr);

cleanup:
    if (pCipherPriKey != NULL) {
        (*env)->ReleaseByteArrayElements(env, priKeyArr, pCipherPriKey, 0);
    }
    if (byteArrayClass != NULL) {
        (*env)->DeleteLocalRef(env, byteArrayClass);
    }
    if (pbkXArr != NULL) {
        (*env)->DeleteLocalRef(env, pbkXArr);
    }
    if (pbkYArr != NULL) {
        (*env)->DeleteLocalRef(env, pbkYArr);
    }
    return params;
}
