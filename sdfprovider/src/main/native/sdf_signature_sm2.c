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

#include "org_openeuler_sdf_wrapper_SDFSM2SignatureNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"
#include "sdf_log.h"

enum {
    SDF_SM2_SIGNATURE_R_IDX= 0,
    SDF_SM2_SIGNATURE_S_IDX = 1,
    SDF_SM2_SIGNATURE_PARAMS_LEN = 2
} SDF_SM2_SIGNATURE_IDX;

jobjectArray SDF_SM2SignatureToObjectArray(JNIEnv *env, SM2Signature* sm2Signature) {
    jbyteArray rArr = NULL;
    jbyteArray sArr = NULL;
    jclass byteArrayClass = NULL;
    jobjectArray params = NULL;

    // r
    rArr = (*env)->NewByteArray(env, SM2_KEY_BUF_LEN);
    if (rArr == NULL) {
        SDF_LOG_ERROR("SDF_SM2SignatureToObjectArray failed to allocate pbkXArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, rArr, 0, SM2_KEY_BUF_LEN, (jbyte *) sm2Signature->r);

    // s
    sArr = (*env)->NewByteArray(env, SM2_KEY_BUF_LEN);
    if (sArr == NULL) {
        SDF_LOG_ERROR("SDF_SM2SignatureToObjectArray failed to allocate pbkYArr");
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, sArr, 0, SM2_KEY_BUF_LEN, (jbyte *) sm2Signature->s);

    byteArrayClass = (*env)->FindClass(env, "[B");
    int arrayLen = SDF_SM2_SIGNATURE_PARAMS_LEN;
    params = (*env)->NewObjectArray(env, arrayLen, byteArrayClass, NULL);
    if (params == NULL) {
        SDF_LOG_ERROR("SDF_SM2SignatureToObjectArray failed to allocate params");
        goto cleanup;
    }
    (*env)->SetObjectArrayElement(env, params, SDF_SM2_SIGNATURE_R_IDX, rArr);
    (*env)->SetObjectArrayElement(env, params, SDF_SM2_SIGNATURE_S_IDX, sArr);

cleanup:
    if (byteArrayClass != NULL) {
        (*env)->DeleteLocalRef(env, byteArrayClass);
    }
    if (rArr != NULL) {
        (*env)->DeleteLocalRef(env, rArr);
    }
    if (sArr != NULL) {
        (*env)->DeleteLocalRef(env, sArr);
    }
    return params;
}

SM2Signature *SDF_ObjectArrayToSM2Signature(JNIEnv *env, jobjectArray params) {
    jbyteArray rArr = NULL;
    jbyteArray sArr = NULL;
    jbyte *rBytes = NULL;
    jbyte *sBytes = NULL;
    SM2Signature *sm2Signature = NULL;

    if ((sm2Signature = malloc(sizeof(SM2Signature))) == NULL) {
        throwSDFRuntimeException(env, "malloc SM2Signature failed");
        goto cleanup;
    }

    // r
    rArr = (*env)->GetObjectArrayElement(env, params, SDF_SM2_SIGNATURE_R_IDX);
    rBytes = (*env)->GetByteArrayElements(env, rArr, 0);
    memcpy(sm2Signature->r, rBytes, SM2_KEY_BUF_LEN);

    // s
    sArr = (*env)->GetObjectArrayElement(env, params, SDF_SM2_SIGNATURE_S_IDX);
    sBytes = (*env)->GetByteArrayElements(env, sArr, 0);
    memcpy(sm2Signature->s, sBytes, SM2_KEY_BUF_LEN);

cleanup:
    if (rBytes) {
        (*env)->ReleaseByteArrayElements(env, rArr, rBytes, 0);
    }
    if (sBytes) {
        (*env)->ReleaseByteArrayElements(env, sArr, sBytes, 0);
    }
    return sm2Signature;
}

JNIEXPORT jobjectArray JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2SignatureNative_nativeSM2Sign(JNIEnv *env, jclass clz,
        jbyteArray priKeyArr, jbyteArray digestArray) {
    unsigned int keyType = DATA_KEY_SM2;
    void *keyHandle = NULL;
    jbyte *data = NULL;
    unsigned int dataLen;
    unsigned char *signature = NULL;
    unsigned int signatureLen;
    SGD_RV rv;
    jobjectArray params = NULL;

    // private key
    keyHandle = SDF_CreateSM2PriKeyHandle(env,priKeyArr);

    // digest data
    dataLen = (*env)->GetArrayLength(env, digestArray);
    if ((data = malloc(dataLen)) == NULL) {
        SDF_LOG_ERROR("malloc pubData failed");
        throwOutOfMemoryError(env, "malloc pubData failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, digestArray, 0, dataLen, data);

    // signature
    signatureLen = sizeof(SM2Signature);
    if ((signature = malloc(signatureLen)) == NULL) {
        SDF_LOG_ERROR("malloc signature failed");
        throwOutOfMemoryError(env, "malloc signature failed");
        goto cleanup;
    }

    // sign
    if ((rv = CDM_AsymSign(keyType, keyHandle, data, dataLen,
            signature, &signatureLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_AsymSign");
        goto cleanup;
    }

    SM2Signature *sm2Signature = (SM2Signature *) signature;
    params = SDF_SM2SignatureToObjectArray(env, sm2Signature);
    if (params == NULL) {
        throwSDFRuntimeException(env, "SDF_SM2SignatureToObjectArray failed");
        goto cleanup;
    }

cleanup:
    if (keyHandle != NULL) {
        CDM_DestroyKeyHandle(keyHandle);
    }
    if (data != NULL) {
        free(data);
    }
    if (signature != NULL) {
        free(signature);
    }

    return params;
}


JNIEXPORT jboolean JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2SignatureNative_nativeSM2Verify(JNIEnv *env, jclass clz,
        jobjectArray pubKeyArr, jbyteArray digestArray, jobjectArray params) {
    unsigned int keyType = DATA_KEY_SM2;
    unsigned char *pubKey = NULL;
    unsigned int pubKeyLen = 0;
    unsigned char *data = NULL;
    unsigned int dataLen = 0;
    unsigned char *signature = NULL;
    unsigned int signatureLen = 0;

    jbyte *rBytes = NULL;
    jbyte *sBytes = NULL;

    SGD_RV rv;
    jboolean result = JNI_FALSE;

    // public key
    pubKey = SDF_CreateSM2PublicKey(env, pubKeyArr,&pubKeyLen);

    // digest data
    dataLen = (*env)->GetArrayLength(env, digestArray);
    if ((data = malloc(dataLen)) == NULL) {
        SDF_LOG_ERROR("malloc pubData failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, digestArray, 0, dataLen, data);

    // signature
    SM2Signature* sm2Signature = SDF_ObjectArrayToSM2Signature(env, params);
    signature = (unsigned char* ) sm2Signature;
    signatureLen = sizeof(SM2Signature);

    if ((rv = CDM_AsymVerify(keyType, pubKey, pubKeyLen, data, dataLen,
            signature, signatureLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_AsymVerify");
        goto cleanup;
    }

    result = JNI_TRUE;
cleanup:
    SDF_FreeSM2PublicKey(pubKey);
    if (data != NULL) {
        free(data);
    }
    if (signature != NULL) {
        free(signature);
    }
    if (rBytes != NULL) {
        free(rBytes);
    }
    if (sBytes != NULL) {
        free(sBytes);
    }
    return result;
}
