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
#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include "sdf_exception.h"

#define SGD_RV int

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

enum SDF_KEY_SIZE {
    SDF_INVALID_VALUE = -1,
    SDF_SYS_ENC_KEY_LEN  = 1024,
    SDF_HMAC_ENC_KEY_LEN  = 1024,
    SDF_SM2_ENC_PRI_KEY_SIZE = 1024,
    SDF_SM2_ENC_PUB_KEY_SIZE = 136,
    SDF_FINISHED_LEN = 12
};

void *SDF_Malloc(size_t num);

void *SDF_Free(void *ptr);
/*ECCrefPublicKey_HW* SDF_GetECCPublickeyFromObj(JNIEnv* env, jobject publicKeyObj);

ECCrefPublicKey_HW* SDF_GetECCPublickeyFromByteArray(JNIEnv* env, jbyteArray xArr, jbyteArray yArr, jint bits);

ECCrefPrivateKey* SDF_GetECCPrivateKeyFromByteArray(JNIEnv* env, jbyteArray keyArr, jint bits);

C_SM2Pairs* SDF_GetEncECCPrivateKeyFromByteArray(JNIEnv* env, jbyteArray keyArr);

void SDF_SetECCCharArrayToJava(JNIEnv *env, jclass clazz, jobject obj, const char *field_name,
                                        const char *field_type, unsigned char *native_array, jsize len);

void SDF_SetECCByteArrayToNative(JNIEnv *env, jclass clazz, jobject obj, const char *field_name,
                                        const char *field_type, char *native_array, jsize len);

jobject SDF_GetECCCipherJavaObject(JNIEnv *env, unsigned char *pucEncData, unsigned int pEDLen);

unsigned char* SDF_NewECCCipherChars(JNIEnv *env, jobject eccCipher_object, unsigned int *eccCipher_len);

void SDF_ReleaseECCCipherChars(unsigned char *pucEncData);*/

unsigned int SDF_GetDigestAlgoId(const char *algoName);

unsigned int SDF_GetSymmetricModeType(const char *modeName);

// get asymmetric public key len
unsigned int SDF_GetAsymmetricPBKLen(unsigned int uiKeyType);

// get asymmetric private key len
unsigned int SDF_GetAsymmetricPRKLen(unsigned int uiKeyType);

// create DEK params
void* SDF_CreateDEKParams(JNIEnv *env, jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId, jbyteArray pin);

// free DEK params
void SDF_FreeDEKParams(JNIEnv *env, void *dekParams);

// get sm2 public key len
unsigned int SDF_GetSM2PublicKeyLen();

// create sm2 public key
unsigned char *SDF_CreateSM2PublicKey(JNIEnv *env, jobjectArray pubKeyArr, unsigned int *pubKeyLen);
// free sm2 public key
void SDF_FreeSM2PublicKey(unsigned char *pubKey);

void *SDF_CreateSM2PriKeyHandle(JNIEnv *env, jbyteArray priKeyArr);
void SDF_FreeSM2PriKeyHandle(void *keyHandle);

jobjectArray SDF_SM2CipherToObjectArray(JNIEnv *env, SM2Cipher *sm2Cipher);
SM2Cipher * SDF_ObjectArrayToSM2Cipher(JNIEnv *env, jobjectArray cipherParams, unsigned int* encDataLen);

// print a memory array of specified length
void SDF_Print_Chars(const char *attrName, unsigned char *p, unsigned int len);

unsigned int SDF_GetSymmetricKeyType(const char *algoName);
unsigned int SDF_GetHmacKeyType(const char *algoName);
unsigned int SDF_GetAsymmetricKeyType(const char *algoName);
