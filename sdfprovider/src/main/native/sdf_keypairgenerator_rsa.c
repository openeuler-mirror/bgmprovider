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

#include "org_openeuler_sdf_wrapper_SDFRSAKeyPairGeneratorNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

static jboolean SDF_SetRSAKeyParams(JNIEnv *env, jobjectArray params, SDF_RSAKeyParamIndex index,
        int size, unsigned char *element) {
    jbyteArray m = (*env)->NewByteArray(env, size);
    if (m == NULL) {
        throwOutOfMemoryError(env, "malloc failed");
        return JNI_FALSE;
    }
    (*env)->SetByteArrayRegion(env, m, 0, size, element);
    (*env)->SetObjectArrayElement(env, params, index, m);
    return JNI_TRUE;
}

jobjectArray SDF_NewRSAKeyParams(JNIEnv *env, unsigned char *pPublicKey, const unsigned char *pCipherPriKey) {
    jobjectArray params = NULL;
    jclass byteArrayClass = NULL;

    int paramLen = SDF_RSA_PRK_PRIME_COEFF_IDX + 1;
    byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        goto cleanup;
    }
    params = (*env)->NewObjectArray(env, paramLen, byteArrayClass, NULL);
    if (params == NULL) {
        goto cleanup;
    }

    // RSA public key parameters (m ,e )
    RSArefPublicKeyEx *publicKey = (RSArefPublicKeyEx *) pPublicKey;
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PBK_M_IDX, ExRSAref_MAX_LEN, publicKey->m)) {
        goto cleanup;
    }
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PBK_E_IDX, ExRSAref_MAX_LEN, publicKey->e)) {
        goto cleanup;
    }

    // RSA private key parameters (d,p,q,pe,qe,coeff)
    RSArefPrivateKeyEx *privateKey = (RSArefPrivateKeyEx *) pCipherPriKey;
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PRK_D_IDX, ExRSAref_MAX_LEN, privateKey->d)) {
        goto cleanup;
    }
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PRK_PRIME_P_IDX, ExRSAref_MAX_PLEN, privateKey->prime[0])) {
        goto cleanup;
    }
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PRK_PRIME_Q_IDX, ExRSAref_MAX_PLEN, privateKey->prime[1])) {
        goto cleanup;
    }
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PRK_PRIME_EXPONENT_P_IDX, ExRSAref_MAX_PLEN, privateKey->pexp[0])) {
        goto cleanup;
    }
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PRK_PRIME_EXPONENT_Q_IDX, ExRSAref_MAX_PLEN, privateKey->pexp[1])) {
        goto cleanup;
    }
    if (!SDF_SetRSAKeyParams(env, params, SDF_RSA_PRK_PRIME_COEFF_IDX, ExRSAref_MAX_PLEN, privateKey->coef)) {
        goto cleanup;
    }

    /*SDF_Print_Chars("m", privateKey->m, ExRSAref_MAX_LEN);
    SDF_Print_Chars("e", privateKey->e, ExRSAref_MAX_LEN);
    SDF_Print_Chars("d", privateKey->d, ExRSAref_MAX_LEN);
    SDF_Print_Chars("p", privateKey->prime[0], ExRSAref_MAX_PLEN);
    SDF_Print_Chars("q", privateKey->prime[1], ExRSAref_MAX_PLEN);
    SDF_Print_Chars("pe", privateKey->pexp[0], ExRSAref_MAX_PLEN);
    SDF_Print_Chars("qe", privateKey->pexp[1], ExRSAref_MAX_PLEN);
    SDF_Print_Chars("coeff", privateKey->coef, ExRSAref_MAX_PLEN);*/
cleanup:
    if (byteArrayClass != NULL) {
        (*env)->DeleteLocalRef(env, byteArrayClass);
    }
    return params;
}

JNIEXPORT jobjectArray JNICALL Java_org_openeuler_sdf_wrapper_SDFRSAKeyPairGeneratorNative_nativeGenerateKeyPair(
        JNIEnv *env, jclass cls, jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId, jbyteArray pin, jint keySize) {
    unsigned int uiAlgID = ALG_SM4;
    unsigned char *IV = NULL;
    unsigned int IVLen = 0;
    void *dekParams = NULL;
    unsigned uiKeyType = DATA_KEY_RSA;
    unsigned char *pPublicKey = NULL;
    unsigned int PBKLen;
    unsigned char *pCipherPriKey = NULL;
    unsigned int PRKLen;

    jobjectArray keyParams = NULL;
    SGD_RV rv;

    if (!(dekParams = SDF_CreateDEKParams(env, kekId, regionId, cdpId, pin))) {
        goto cleanup;
    }

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

    if ((rv = CDM_CreateDataKeypairsWithoutPlaintext(uiAlgID, IV, IVLen,
            dekParams, uiKeyType, keySize,
            pPublicKey, &PBKLen, pCipherPriKey, &PRKLen)) != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    keyParams = SDF_NewRSAKeyParams(env, pPublicKey, pCipherPriKey);
    if (keyParams == NULL) {
        throwSDFRuntimeException(env, "SDF_NewKeyParams failed");
        goto cleanup;
    }
cleanup:
    SDF_FreeDEKParams(env, dekParams);
    if (pPublicKey) {
        free(pPublicKey);
    }
    if (pCipherPriKey) {
        free(pCipherPriKey);
    }
    return keyParams;
}
