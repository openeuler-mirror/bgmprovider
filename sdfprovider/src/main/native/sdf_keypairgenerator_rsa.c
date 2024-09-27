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

#include "org_openeuler_sdf_wrapper_SDFRSAKeyPairGeneratorNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

#define SDF_RSA_KEY_TYPE_1024  (SDF_ASYMMETRIC_KEY_TYPE_RSA | 0x01000000)
#define SDF_RSA_KEY_TYPE_2048  (SDF_ASYMMETRIC_KEY_TYPE_RSA | 0x02000000)
#define SDF_RSA_KEY_TYPE_3072  (SDF_ASYMMETRIC_KEY_TYPE_RSA | 0x03000000)
#define SDF_RSA_KEY_TYPE_4096  (SDF_ASYMMETRIC_KEY_TYPE_RSA | 0x04000000)

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

unsigned int SDF_GetRSAKeyType(int keySize) {
    if (keySize == 1024) {
        return SDF_RSA_KEY_TYPE_1024;
    } else if (keySize == 2048) {
        return SDF_RSA_KEY_TYPE_2048;
    } else if (keySize == 3072) {
        return SDF_RSA_KEY_TYPE_3072;
    } else if (keySize == 4096) {
        return SDF_RSA_KEY_TYPE_4096;
    } else {
        return SDF_INVALID_VALUE;
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFRSAKeyPairGeneratorNative
 * Method:    nativeGenerateKeyPair
 * Signature: (J[B[B[B[BI)[[B
 */
JNIEXPORT jobjectArray JNICALL Java_org_openeuler_sdf_wrapper_SDFRSAKeyPairGeneratorNative_nativeGenerateKeyPair(
        JNIEnv *env, jclass cls, jlong sessionHandleAddr, jbyteArray kekId, jbyteArray regionId,
        jbyteArray cdpId, jbyteArray pin, jint keySize) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned int uiAlgID = SGD_SM4_ECB;
    unsigned char *IV = NULL;
    unsigned int IVLen = 0;
    jbyte *uiPIN = NULL;
    unsigned int uiPINLen = 0;
    KEKInfo *uiKEKInfo = NULL;
    unsigned uiKeyType = SDF_ASYMMETRIC_KEY_TYPE_RSA;
    unsigned char *pPublicKey = NULL;
    unsigned int PBKLen;
    unsigned char *pCipherPriKey = NULL;
    unsigned int PRKLen;

    jobjectArray keyParams = NULL;
    SGD_RV rv;

    /*uiKEKInfo = SDF_NewKEKInfo(env, kekId, regionId, cdpId);
    if (uiKEKInfo == NULL) {
        throwSDFRuntimeException(env, "SDF_NewKEKInfo failed");
        goto cleanup;
    }

    if (pin) {
        uiPIN = (*env)->GetByteArrayElements(env, pin, NULL);
        uiPINLen = (*env)->GetArrayLength(env, pin);
    }*/

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

    uiKeyType = SDF_GetRSAKeyType(keySize);

    if ((rv = SDF_HW_CreateDataKeyPairsWithoutPlaintext(hSessionHandle, uiAlgID, IV, IVLen,
            uiPIN, uiPINLen, uiKEKInfo, uiKeyType,
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
    /*if (uiPIN != NULL) {
        (*env)->ReleaseByteArrayElements(env, pin, uiPIN, 0);
    }*/
    /*if (uiKEKInfo != NULL) {
        SDF_ReleaseKEKInfo(uiKEKInfo);
    }*/
    if (pPublicKey) {
        free(pPublicKey);
    }
    if (pCipherPriKey) {
        free(pCipherPriKey);
    }
    return keyParams;
}
