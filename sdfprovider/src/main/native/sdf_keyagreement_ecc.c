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

#include "org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative.h"
#include "sdf.h"
#include "sdf_exception.h"
#include "sdf_util.h"

/*
 * Class:     org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative
 * Method:    decodeECCPreMasterKey
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative_decodeECCPreMasterKey(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jbyteArray localEncPriKeyArr, jobject encryptedSecret, jint bits) {
    // sessionHandle
    SGD_HANDLE sessionHandle = (SGD_HANDLE) sessionHandleAddr;
    C_SM2Pairs *encPrivateKey = NULL;
    unsigned char *uiPrivateKey = NULL;
    unsigned int uiPIKLen;
    unsigned char encPreMasterKey[SYSCKEY_LEN] = {0};
    unsigned int encPreMasterKeyLen = 0;
    jbyteArray keyArr = NULL;
    unsigned char *pucEncData = NULL;
    unsigned int pEDLen;
    SGD_RV rv = 0;

    pucEncData = SDF_NewECCCipherChars(env, encryptedSecret, &pEDLen);
    // get Enc Key
    if ((encPrivateKey = SDF_GetEncECCPrivateKeyFromByteArray(env, localEncPriKeyArr)) == NULL) {
        throwNullPointerException(env, "Unable to convert privateKey.");
        goto cleanup;
    }

    // 0-SM2, 1-RSA
    uiPrivateKey = (unsigned char *) &encPrivateKey->SM2PriCKey;
    uiPIKLen = SYSCKEY_LEN;
    rv = SDF_HW_PreMasterKeyExchange(sessionHandle, SDF_ASYMMETRIC_KEY_TYPE_SM2,
            uiPrivateKey, uiPIKLen, pucEncData,pEDLen, encPreMasterKey, &encPreMasterKeyLen);
    if (rv != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    // new keyArr
    keyArr = (*env)->NewByteArray(env, encPreMasterKeyLen);
    (*env)->SetByteArrayRegion(env, keyArr, 0, encPreMasterKeyLen, (jbyte *) encPreMasterKey);
cleanup:
    if (pucEncData != NULL) {
        SDF_ReleaseECCCipherChars(pucEncData);
    }
    if (encPrivateKey != NULL) {
        free(encPrivateKey);
    }
    return keyArr;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative
 * Method:    generateECCPreMasterKey
 * Signature: (J[B[B[B[BLorg/openeuler/sdf/wrapper/entity/SDFECCrefPublicKey;[BII)Lorg/openeuler/sdf/wrapper/entity/SDFECCCipherEntity;
 */
JNIEXPORT jobject JNICALL
Java_org_openeuler_sdf_wrapper_SDFECCKeyAgreementNative_generateECCPreMasterKey(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jbyteArray kekIdArr, jbyteArray regionIdArr, jbyteArray cdpIdArr, jbyteArray PINArr,
        jobject publicKeyObj, jbyteArray preMasterKeyArr, jint preMasterKeyLen, jint clientVersion) {
    // sessionHandle
    SGD_HANDLE sessionHandle = (SGD_HANDLE) sessionHandleAddr;
    ECCrefPublicKey_HW *publicKey = NULL;
    KEKInfo *kekInfo = NULL;
    jbyte *PINBytes = NULL;
    int PinLen = 0;
    jobject eccCipher_object = NULL;
    SGD_RV rv;
    // preMaster is CipherKey, encryptedKey is normalKey encrypted by public
    unsigned int preMasterKeySize = SYSCKEY_LEN;
    unsigned int encryptedKeySize = sizeof(ECCCipher) + preMasterKeyLen;
    unsigned char preMasterKey[preMasterKeySize];
    unsigned char encryptedKey[encryptedKeySize];

    if (PINArr != NULL) {
        PINBytes = (*env)->GetByteArrayElements(env, PINArr, NULL);
        PinLen = (*env)->GetArrayLength(env, PINArr);
    }

    kekInfo = SDF_NewKEKInfo(env, kekIdArr, regionIdArr, cdpIdArr);

    // get publicKey
    if ((publicKey = SDF_GetECCPublickeyFromObj(env, publicKeyObj)) == NULL) {
        throwOutOfMemoryError(env, "GenerateECCPreMasterKey malloc failed. Unable to convert publicKey.");
        goto cleanup;
    }
    // uiKeyType 0=SM2, 1=RSA
    rv = SDF_HW_CreatePreMasterKey(sessionHandle, SGD_SM4_ECB, NULL, 0, PINBytes, PinLen, kekInfo,
            SDF_ASYMMETRIC_KEY_TYPE_SM2, (unsigned char *) publicKey, sizeof(ECCrefPublicKey_HW), preMasterKey,
            &preMasterKeyLen, encryptedKey, &encryptedKeySize, clientVersion);
    if (rv != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    (*env)->SetByteArrayRegion(env, preMasterKeyArr, 0, preMasterKeySize, (jbyte *) preMasterKey);

    eccCipher_object = SDF_GetECCCipherJavaObject(env, encryptedKey, encryptedKeySize);
cleanup:
    if (PINBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, PINArr, PINBytes, 0);
    }
    if (kekInfo != NULL) {
        SDF_ReleaseKEKInfo(kekInfo);
    }
    if (publicKey != NULL) {
        free(publicKey);
    }
    return eccCipher_object;
}



