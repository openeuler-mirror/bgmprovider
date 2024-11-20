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

#include <string.h>
#include "org_openeuler_sdf_wrapper_SDFSM2SignatureNative.h"
#include "sdf.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"
/*
 * Class:     org_openeuler_sdf_wrapper_SDFSM2SignatureNative
 * Method:    nativeSM2Sign
 * Signature: (J[BI[BLorg/openeuler/sdf/wrapper/entity/SDFECCSignature;)V
 */
JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2SignatureNative_nativeSM2Sign
        (JNIEnv *env, jclass clz, jlong sessionAddress, jbyteArray privateKeyArray, jint bits,
                jbyteArray digestArray, jobject signature) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionAddress;
    unsigned int curveLen = (bits + 7) / 8;
    unsigned int uiKeyType = SDF_SIGNATURE_KEY_TYPE_SM2;
    jbyte *uiPriKey = NULL;
    unsigned int uiPIKLen;
    jbyte *pucData = NULL;
    unsigned int uiDataLength;
    unsigned char *pucSignature = NULL;
    unsigned int pSNLen;
    SGD_RV rv;

    // uiPriKey
    uiPIKLen = (*env)->GetArrayLength(env, privateKeyArray);
    if ((uiPriKey = malloc(uiPIKLen)) == NULL) {
        SDF_LOG_ERROR("malloc uiPriKey failed");
        throwOutOfMemoryError(env, "malloc pubData failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, privateKeyArray, 0, uiPIKLen, uiPriKey);

    // pubData
    uiDataLength = (*env)->GetArrayLength(env, digestArray);
    if ((pucData = malloc(uiDataLength)) == NULL) {
        SDF_LOG_ERROR("malloc pubData failed");
        throwOutOfMemoryError(env, "malloc pubData failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, digestArray, 0, uiDataLength, pucData);

    // pucSignature
    if ((pucSignature = malloc(sizeof(ECCSignature_HW))) == NULL) {
        SDF_LOG_ERROR("malloc pucSignature failed");
        throwOutOfMemoryError(env, "malloc pucSignature failed");
        goto cleanup;
    }

    // sign
    if ((rv = SDF_HW_AsymSign(hSessionHandle, uiKeyType, uiPriKey, uiPIKLen,
            pucData, uiDataLength, pucSignature, &pSNLen)) != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    ECCSignature_HW *eccSignature = (ECCSignature_HW *) pucSignature;
    /*SDF_Print_Chars("eccSignature.r", eccSignature->r, ECCref_MAX_LEN_HW);
    SDF_Print_Chars("eccSignature.s", eccSignature->s, ECCref_MAX_LEN_HW);*/

    jclass signatureClass = (*env)->GetObjectClass(env, signature);
    SDF_SetECCCharArrayToJava(env, signatureClass, signature, "r", "[B",
            eccSignature->r, curveLen);
    SDF_SetECCCharArrayToJava(env, signatureClass, signature, "s", "[B",
            eccSignature->s, curveLen);
cleanup:
    if (uiPriKey != NULL) {
        free(uiPriKey);
    }
    if (pucData != NULL) {
        free(pucData);
    }
    if (pucSignature != NULL) {
        free(pucSignature);
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSM2SignatureNative
 * Method:    nativeSM2Verify
 * Signature: (J[B[BI[BLorg/openeuler/sdf/wrapper/entity/SDFECCSignature;)Z
 */
JNIEXPORT jboolean JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2SignatureNative_nativeSM2Verify
        (JNIEnv *env, jclass clz, jlong sessionAddress, jbyteArray xArr, jbyteArray yArr, jint bits,
                jbyteArray digestArray, jobject signature) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionAddress;
    unsigned int uiKeyType = SDF_SIGNATURE_KEY_TYPE_SM2;
    unsigned char *uiPublicKey = NULL;
    unsigned int uiPBKLen;
    unsigned char *pucData = NULL;
    unsigned int uiDataLength;
    unsigned char *pucSignature = NULL;
    unsigned int pSNLen;

    jbyte *rBytes = NULL;
    jbyte *sBytes = NULL;

    SGD_RV rv;
    jboolean result = JNI_FALSE;

    uiPublicKey = SDF_NewECCrefPublicKeyChars(env, xArr, yArr, bits);
    uiPBKLen = SDF_GetECCrefPublicKeyLen();


    uiDataLength = (*env)->GetArrayLength(env, digestArray);
    if ((pucData = malloc(uiDataLength)) == NULL) {
        SDF_LOG_ERROR("malloc pubData failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, digestArray, 0, uiDataLength, pucData);

    // eccSignature
    jclass signatureClass = (*env)->GetObjectClass(env, signature);
    // r
    jfieldID rFieldId = (*env)->GetFieldID(env, signatureClass, "r", "[B");
    jbyteArray rArray = (*env)->GetObjectField(env, signature, rFieldId);
    if ((rBytes = malloc(ECCref_MAX_LEN_HW)) == NULL) {
        throwOutOfMemoryError(env, "malloc rBytes failed");
        goto cleanup;
    }
    memset(rBytes, 0, ECCref_MAX_LEN_HW);
    jint rLen = (*env)->GetArrayLength(env, rArray);
    (*env)->GetByteArrayRegion(env, rArray, 0, rLen, rBytes);

    // s
    jfieldID sFieldId = (*env)->GetFieldID(env, signatureClass, "s", "[B");
    jbyteArray sArray = (*env)->GetObjectField(env, signature, sFieldId);
    if ((sBytes = malloc(ECCref_MAX_LEN_HW)) == NULL) {
        throwOutOfMemoryError(env, "malloc sBytes failed");
        goto cleanup;
    }
    memset(sBytes, 0, ECCref_MAX_LEN_HW);
    jint sLen = (*env)->GetArrayLength(env, sArray);
    (*env)->GetByteArrayRegion(env, sArray, 0, sLen, sBytes);

    pSNLen = sizeof(ECCSignature_HW);
    if ((pucSignature = malloc(pSNLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc eccSignature failed");
        goto cleanup;
    }
    ECCSignature_HW *eccSignature = (ECCSignature_HW *) pucSignature;
    memcpy(eccSignature->r, rBytes, ECCref_MAX_LEN_HW);
    memcpy(eccSignature->s, sBytes, ECCref_MAX_LEN_HW);

    if ((rv = SDF_HW_AsymVerify(hSessionHandle, uiKeyType, uiPublicKey, uiPBKLen, pucData, uiDataLength,
            pucSignature, pSNLen)) != SDR_OK) {
        SDF_LOG_ERROR("SDF_HW_AsymVerify failed, rv=%lx", rv);
        goto cleanup;
    }

    result = JNI_TRUE;
cleanup:
    SDF_ReleaseECCrefPubicKeyChars(uiPublicKey);
    if (pucData != NULL) {
        free(pucData);
    }
    if (pucSignature != NULL) {
        free(pucSignature);
    }
    if (rBytes != NULL) {
        free(rBytes);
    }
    if (sBytes != NULL) {
        free(sBytes);
    }
    return result;
}
