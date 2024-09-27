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

#include "org_openeuler_sdf_wrapper_SDFSM2CipherNative.h"
#include "sdf.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"
#include <stdlib.h>

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSM2CipherNative
 * Method:    nativeSM2Encrypt
 * Signature: (J[B[B[BI)Lorg/openeuler/sdf/wrapper/entity/SDFECCCipherEntity;
 */
JNIEXPORT jobject JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2CipherNative_nativeSM2Encrypt(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jbyteArray xArr, jbyteArray yArr, jint bits, jbyteArray pubDataArr) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned int uiKeyType = SDF_ASYMMETRIC_KEY_TYPE_SM2;
    unsigned char *uiPublicKey = NULL;
    unsigned int uiPBKLen;
    jbyte *pucData = NULL;
    unsigned int uiDataLength;
    unsigned char *pucEncData = NULL;
    unsigned int pEDLen;

    jobject eccCipher_object = NULL;

    SGD_RV rv;

    // uiPublicKey, uiPBKLen
    uiPublicKey = SDF_NewECCrefPublicKeyChars(env, xArr, yArr, bits);
    uiPBKLen = SDF_GetECCrefPublicKeyLen();

    // get pucData,uiDataLength
    pucData = (*env)->GetByteArrayElements(env, pubDataArr, 0);
    uiDataLength = (*env)->GetArrayLength(env, pubDataArr);
    pEDLen = sizeof(ECCCipher) + uiDataLength;
    if ((pucEncData = malloc(pEDLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pucEncData failed");
        goto cleanup;
    }

    /* SDF_LOG_DEBUG("hSessionHandle=%p", hSessionHandle);
     SDF_LOG_DEBUG("uiKeyType=%d", uiKeyType);
     SDF_Print_Chars("uiPublicKey", uiPublicKey, uiPBKLen);
     SDF_LOG_DEBUG("uiPBKLen=%d", uiPBKLen);
     SDF_LOG_DEBUG("pucData=%s", pucData);
     SDF_LOG_DEBUG("uiDataLength=%d", uiDataLength);*/

    if ((rv = SDF_HW_AsymEncrypt(hSessionHandle, uiKeyType, uiPublicKey, uiPBKLen,
            pucData, uiDataLength, pucEncData, &pEDLen)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    /*SDF_Print_Chars("pucEncData", pucEncData, pEDLen);
    SDF_LOG_DEBUG("pEDLen=%d", pEDLen);*/

    eccCipher_object = SDF_GetECCCipherJavaObject(env, pucEncData, pEDLen);

cleanup:
    if (pucData != NULL) {
        (*env)->ReleaseByteArrayElements(env, pubDataArr, pucData, 0);
    }
    if (uiPublicKey != NULL) {
        SDF_ReleaseECCrefPubicKeyChars(uiPublicKey);
    }
    if (pucEncData != NULL) {
        free(pucEncData);
    }
    return eccCipher_object;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSM2CipherNative
 * Method:    nativeSM2Decrypt
 * Signature: (J[BLorg/openeuler/sdf/wrapper/entity/SDFECCCipherEntity;I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2CipherNative_nativeSM2Decrypt(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jbyteArray uiPriKeyArr, jobject eccCipher, jint bits) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned int uiKeyType = SDF_ASYMMETRIC_KEY_TYPE_SM2;
    unsigned char *uiPriKey = NULL;
    unsigned int uiPIKLen;

    unsigned char *pucEncData = NULL;
    unsigned int pEDLen;

    jbyte *pucData = NULL;
    unsigned int puiDataLength;
    jbyteArray pucDataArray = NULL;

    SGD_RV rv;

    uiPriKey = (*env)->GetByteArrayElements(env, uiPriKeyArr, 0);
    uiPIKLen = (*env)->GetArrayLength(env, uiPriKeyArr);

    pucEncData = SDF_NewECCCipherChars(env, eccCipher, &pEDLen);
    if (pucEncData == NULL) {
        goto cleanup;
    }

    puiDataLength = pEDLen - (ECCref_MAX_LEN_HW * 2 + 32 + sizeof(int));
    if ((pucData = malloc(puiDataLength)) == NULL) {
        throwOutOfMemoryError(env, "malloc pucData failed");
        goto cleanup;
    }
/*
    SDF_LOG_DEBUG("uiKeyType=%d",uiKeyType);
    SDF_Print_Chars("uiPriKey", uiPriKey, uiPIKLen);
    SDF_LOG_DEBUG("uiPIKLen=%d",uiPIKLen);
    SDF_Print_Chars("pucEncData", pucEncData, pEDLen);
    SDF_LOG_DEBUG("pEDLen=%d",pEDLen);*/

    if ((rv = SDF_HW_AsymDecrypt(hSessionHandle, uiKeyType, uiPriKey, uiPIKLen, pucEncData, pEDLen, pucData,
            &puiDataLength) != SDR_OK)) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    /*SDF_LOG_DEBUG("pucData=%s", pucData);
    SDF_LOG_DEBUG("puiDataLength=%d",puiDataLength);*/

    pucDataArray = (*env)->NewByteArray(env, puiDataLength);
    (*env)->SetByteArrayRegion(env, pucDataArray, 0, puiDataLength, pucData);
cleanup:
    if (uiPriKey) {
        (*env)->ReleaseByteArrayElements(env, uiPriKeyArr, uiPriKey, 0);
    }
    if (pucEncData) {
        SDF_ReleaseECCCipherChars(pucEncData);
    }
    if (pucData) {
        free(pucData);
    }
    return pucDataArray;
}
