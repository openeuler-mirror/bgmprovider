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

#include "sdf.h"
#include "sdf_exception.h"
#include <stdlib.h>
#include <string.h>
#include <jni.h>

#define SYSCKEY_LEN 512
#define HMAC_KEY_LEN sizeof(HMACKey)
#define SDF_INVALID_VALUE -1
#define CLASS_SDFECCCipherEntity "org/openeuler/sdf/wrapper/entity/SDFECCCipherEntity"

#define HW_KEYDESTROY_MASK 0x00010000

// RSA Key index.
typedef enum SDF_RSAKeyParamIndex {
    // RSA public key parameter index
    SDF_RSA_PBK_M_IDX = 0,
    SDF_RSA_PBK_E_IDX = 1,

    // RSA private key parameter index
    SDF_RSA_PRK_D_IDX = 2,
    SDF_RSA_PRK_PRIME_P_IDX = 3,
    SDF_RSA_PRK_PRIME_Q_IDX = 4,
    SDF_RSA_PRK_PRIME_EXPONENT_P_IDX = 5,
    SDF_RSA_PRK_PRIME_EXPONENT_Q_IDX = 6,
    SDF_RSA_PRK_PRIME_COEFF_IDX = 7,
} SDF_RSAKeyParamIndex;

enum SDF_CTX_TYPE {
    SDF_CTX_TYPE_SYMMETRIC = 0,
    SDF_CTX_TYPE_DIGEST = 1,
    SDF_CTX_TYPE_HMAC = 2
};

enum SDF_ASYMMETRIC_KEY_TYPE {
    SDF_ASYMMETRIC_KEY_TYPE_SM2 = 0,
    SDF_ASYMMETRIC_KEY_TYPE_RSA = 1,
    SDF_ASYMMETRIC_KEY_TYPE_ECC = 2
};

enum SDF_SIGNATURE_KEY_TYPE {
    SDF_SIGNATURE_KEY_TYPE_SM2 = 0,
    SDF_SIGNATURE_KEY_TYPE_ECC = 0
};

jbyteArray SDF_GetByteArrayFromCharArr(JNIEnv* env, const char* charArr, int arrLen);

ECCrefPublicKey_HW* SDF_GetECCPublickeyFromObj(JNIEnv* env, jobject publicKeyObj);

ECCrefPublicKey_HW* SDF_GetECCPublickeyFromByteArray(JNIEnv* env, jbyteArray xArr, jbyteArray yArr, jint bits);

ECCrefPrivateKey* SDF_GetECCPrivateKeyFromByteArray(JNIEnv* env, jbyteArray keyArr, jint bits);

C_SM2Pairs* SDF_GetEncECCPrivateKeyFromByteArray(JNIEnv* env, jbyteArray keyArr);

void SDF_SetECCCharArrayToJava(JNIEnv *env, jclass clazz, jobject obj, const char *field_name,
                                        const char *field_type, unsigned char *native_array, jsize len);

void SDF_SetECCByteArrayToNative(JNIEnv *env, jclass clazz, jobject obj, const char *field_name,
                                        const char *field_type, char *native_array, jsize len);

jobject SDF_GetECCCipherJavaObject(JNIEnv *env, unsigned char *pucEncData, unsigned int pEDLen);

unsigned char* SDF_NewECCCipherChars(JNIEnv *env, jobject eccCipher_object, unsigned int *eccCipher_len);

void SDF_ReleaseECCCipherChars(unsigned char *pucEncData);

unsigned int SDF_GetDigestAlgoId(const char *algoName);

unsigned int SDF_GetSymmetricAlgoId(const char *algoName);

// get asymmetric public key len
unsigned int SDF_GetAsymmetricPBKLen(unsigned int uiKeyType);

// get asymmetric private key len
unsigned int SDF_GetAsymmetricPRKLen(unsigned int uiKeyType);

// new KEKInfo
KEKInfo* SDF_NewKEKInfo(JNIEnv *env, jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId);

// release KEKInfo
void SDF_ReleaseKEKInfo(KEKInfo *uiKEKInfo);


unsigned int SDF_GetECCrefPublicKeyLen();

unsigned char *SDF_NewECCrefPublicKeyChars(JNIEnv *env, jbyteArray xArr, jbyteArray yArr, jint bits);

void SDF_ReleaseECCrefPubicKeyChars(unsigned char *uiPublicKey);

// print a memory array of specified length
void SDF_Print_Chars(const char *attrName, unsigned char *p, unsigned int len);