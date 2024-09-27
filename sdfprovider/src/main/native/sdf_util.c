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

#include <stdbool.h>
#include "sdf_util.h"
#include "sdf_log.h"

jbyteArray SDF_GetByteArrayFromCharArr(JNIEnv* env, const char* charArr, int arrLen)
{
    if (charArr == NULL) {
        return NULL;
    }
    if (arrLen <= 0) {
        return NULL;
    }
    jbyteArray javaBytes = (*env)->NewByteArray(env, arrLen);
    if (javaBytes == NULL) {
        throwOutOfMemoryError(env, "New byte array failed.");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, javaBytes, 0, arrLen, (jbyte*)charArr);
    return javaBytes;
}

ECCrefPublicKey_HW* SDF_GetECCPublickeyFromObj(JNIEnv* env, jobject publicKeyObj)
{
    // convert
    jclass publicKeyClass = (*env)->GetObjectClass(env, publicKeyObj);
    jfieldID bitsFieldId = (*env)->GetFieldID(env, publicKeyClass, "bits", "I");
    jint bits = (jint) (*env)->GetIntField(env, publicKeyObj, bitsFieldId);
    jfieldID xFieldId = (*env)->GetFieldID(env, publicKeyClass, "x", "[B");
    jbyteArray xArray = (*env)->GetObjectField(env, publicKeyObj, xFieldId);
    jfieldID yFieldId = (*env)->GetFieldID(env, publicKeyClass, "y", "[B");
    jbyteArray yArray = (*env)->GetObjectField(env, publicKeyObj, yFieldId);
    if (publicKeyClass != NULL) {
        (*env)->DeleteLocalRef(env, publicKeyClass);
    }
    return SDF_GetECCPublickeyFromByteArray(env, xArray, yArray, bits);
}

ECCrefPublicKey_HW* SDF_GetECCPublickeyFromByteArray(JNIEnv* env, jbyteArray xArr, jbyteArray yArr, jint bits)
{
    ECCrefPublicKey_HW* publicKey = NULL;
    unsigned int PBKLen = SDF_GetAsymmetricPBKLen(SDF_ASYMMETRIC_KEY_TYPE_SM2);

    jsize xLen;
    jsize yLen;

    if (xArr == NULL) {
        return NULL;
    }
    if (yArr == 0) {
        return NULL;
    }

    xLen = (*env)->GetArrayLength(env, xArr);
    yLen = (*env)->GetArrayLength(env, yArr);

    if((publicKey = malloc(PBKLen)) == NULL) {
        throwOutOfMemoryError(env, "SDF_GetECCPublickeyFromByteArray failed. Unable to allocate in 'publicKey' buffer");
        goto cleanup;
    }
    memset(publicKey, 0, PBKLen);

    (*env)->GetByteArrayRegion(env, xArr, 0, xLen, publicKey->x);
    (*env)->GetByteArrayRegion(env, yArr, 0, yLen, publicKey->y);
    publicKey->bits = bits;
cleanup:
    return publicKey;
}

// Get Normal PrivateKey
ECCrefPrivateKey* SDF_GetECCPrivateKeyFromByteArray(JNIEnv* env, const jbyteArray keyArr, jint bits)
{
    ECCrefPrivateKey* privateKey = NULL;
    jsize keyLen = 0;

    if (keyArr == NULL) {
        return NULL;
    }
    if ((privateKey = malloc(sizeof(ECCrefPrivateKey))) == NULL) {
        throwOutOfMemoryError(env, "SDF_GetECCPrivateKeyFromByteArray failed. Unable to allocate in 'privateKey' buffer");
        goto cleanup;
    }
    keyLen = (*env)->GetArrayLength(env, keyArr);
    memset(privateKey, 0, sizeof(ECCrefPrivateKey));
    (*env)->GetByteArrayRegion(env, keyArr, 0, keyLen, &(privateKey->K[ECCref_MAX_LEN_HW - keyLen]));
    privateKey->bits = bits;
cleanup:
    return privateKey;
}

// Get Enc PrivateKey
C_SM2Pairs* SDF_GetEncECCPrivateKeyFromByteArray(JNIEnv* env, const jbyteArray keyArr)
{
    C_SM2Pairs* privateKey = NULL;
    jsize keyLen = 0;

    if (keyArr == NULL) {
        return NULL;
    }
    if ((privateKey = malloc(sizeof(C_SM2Pairs))) == NULL) {
        throwOutOfMemoryError(env, "SDF_GetEncECCPrivateKeyFromByteArray failed. Unable to allocate in 'privateKey' buffer");
        goto cleanup;
    }
    keyLen = (*env)->GetArrayLength(env, keyArr);
    memset(privateKey, 0, sizeof(C_SM2Pairs));
    (*env)->GetByteArrayRegion(env, keyArr, 0, keyLen, (jbyte*)privateKey);
cleanup:
    return privateKey;
}

void SDF_SetECCCharArrayToJava(JNIEnv *env, jclass clazz, jobject obj, const char *field_name,
                                        const char *field_type, unsigned char *native_array, jsize len)
{
    // new byte object
    jbyteArray byteArray = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, byteArray, 0, len, (jbyte*) native_array);
    // set byte to java object
    jfieldID id = (*env)->GetFieldID(env, clazz, field_name, field_type);
    (*env)->SetObjectField(env, obj, id, byteArray);
}

void SDF_SetECCByteArrayToNative(JNIEnv *env, jclass clazz, jobject obj, const char *field_name,
                                        const char *field_type, char *native_array, jsize len)
{
    jfieldID id = (*env)->GetFieldID(env, clazz, field_name, field_type);
    jbyteArray field = (*env)->GetObjectField(env, obj, id);
    (*env)->GetByteArrayRegion(env, field, 0, len, native_array);
}

jobject SDF_GetECCCipherJavaObject(JNIEnv *env, unsigned char *pucEncData, unsigned int pEDLen) {
    ECCCipher_HW_Ex *eccCipher = NULL;
    jclass eccCipher_class = NULL;
    jmethodID init_mid;
    jfieldID cLength_fid;
    jobject eccCipher_object = NULL;

    // char* to eccCipher
    if ((eccCipher = malloc(pEDLen)) == NULL) {
        SDF_LOG_ERROR("malloc ECCCipher failed");
        goto cleanup;
    }
    memcpy(eccCipher, pucEncData, pEDLen);

    eccCipher_class = (*env)->FindClass(env, CLASS_SDFECCCipherEntity);
    if (eccCipher_class == NULL) {
        SDF_LOG_ERROR("FindClass CLASS_SDFECCCipherEntity failed");
        goto cleanup;
    }
    init_mid = (*env)->GetMethodID(env, eccCipher_class, "<init>", "()V");
    eccCipher_object = (*env)->NewObject(env, eccCipher_class, init_mid);

    // set cLength fieled
    cLength_fid = (*env)->GetFieldID(env, eccCipher_class, "cLength", "I");
    (*env)->SetIntField(env, eccCipher_object, cLength_fid, eccCipher->L);

    // set x fieled
    SDF_SetECCCharArrayToJava(env, eccCipher_class, eccCipher_object, "x", "[B",
            eccCipher->x, sizeof(eccCipher->x));
    // set y fieled
    SDF_SetECCCharArrayToJava(env, eccCipher_class, eccCipher_object, "y", "[B",
            eccCipher->y, sizeof(eccCipher->y));
    // set M fieled
    SDF_SetECCCharArrayToJava(env, eccCipher_class, eccCipher_object, "M", "[B",
            eccCipher->M, sizeof(eccCipher->M));
    // set C fieled
    SDF_SetECCCharArrayToJava(env, eccCipher_class, eccCipher_object, "C", "[B",
            eccCipher->C, eccCipher->L);
cleanup:
    if (eccCipher) {
        free(eccCipher);
    }
    if (eccCipher_class) {
        (*env)->DeleteLocalRef(env, eccCipher_class);
    }
    return eccCipher_object;
}

unsigned char* SDF_NewECCCipherChars(JNIEnv *env, jobject eccCipher_object, unsigned int *eccCipher_len) {
    ECCCipher_HW_Ex *eccCipher = NULL;
    jclass eccCipher_class = NULL;
    jfieldID cLength_fid;

    eccCipher_class = (*env)->FindClass(env, CLASS_SDFECCCipherEntity);
    if (eccCipher_class == NULL) {
        SDF_LOG_ERROR("FindClass CLASS_SDFECCCipherEntity failed");
        goto cleanup;
    }
    cLength_fid = (*env)->GetFieldID(env, eccCipher_class, "cLength", "I");
    unsigned cLength = (*env)->GetIntField(env, eccCipher_object, cLength_fid);

    unsigned int pEDLen = ECCref_MAX_LEN_HW * 2 + 32 + cLength + sizeof(int);
    if ((eccCipher = malloc(pEDLen)) == NULL) {
        SDF_LOG_ERROR("malloc ECCCipher failed");
        goto cleanup;
    }
    memset(eccCipher, 0, pEDLen);

    *eccCipher_len = pEDLen;

    // set L fieled
    eccCipher->L = cLength;

    // set x fieled
    SDF_SetECCByteArrayToNative(env, eccCipher_class, eccCipher_object, "x", "[B",
            eccCipher->x, sizeof(eccCipher->x));
    // set y fieled
    SDF_SetECCByteArrayToNative(env, eccCipher_class, eccCipher_object, "y", "[B",
            eccCipher->y, sizeof(eccCipher->y));

    // set M fieled
    SDF_SetECCByteArrayToNative(env, eccCipher_class, eccCipher_object, "M", "[B", eccCipher->M, 32);
    // set clength fieled
    SDF_SetECCByteArrayToNative(env, eccCipher_class, eccCipher_object, "C", "[B", eccCipher->C, cLength);

cleanup:
    if (eccCipher_class != NULL) {
        (*env)->DeleteLocalRef(env, eccCipher_class);
    }
    return (unsigned char *) eccCipher;
}

void SDF_ReleaseECCCipherChars(unsigned char *pucEncData) {
    if (pucEncData == NULL) {
        return;
    }
    free(pucEncData);
}

unsigned int SDF_GetDigestAlgoId(const char *algoName) {
    if (strcmp(algoName, "SM3") == 0) {
        return SGD_SM3;
    } else if (strcmp(algoName, "SHA-256") == 0) {
        return SGD_SHA256;
    } else if (strcmp(algoName, "SHA-384") == 0) {
        return SGD_SHA384;
    } else if (strcmp(algoName, "SHA-512") == 0) {
        return SGD_SHA512;
    } else if (strcmp(algoName, "SHA-1") == 0) {
        return SGD_SHA1;
    } else if (strcmp(algoName, "SHA-224") == 0) {
        return SGD_SHA224;
    } else if (strcmp(algoName, "MD5") == 0) {
        return SGD_MD5;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetSM1AlgoId(const char *algoName) {
    if (strcmp(algoName, "SM1-ECB") == 0) {
        return SGD_SM1_ECB;
    } else if (strcmp(algoName, "SM1-CBC") == 0) {
        return SGD_SM1_CBC;
    } else if (strcmp(algoName, "SM1-CFB") == 0) {
        return SGD_SM1_CFB;
    } else if (strcmp(algoName, "SM1-OFB") == 0) {
        return SGD_SM1_OFB;
    } else if (strcmp(algoName, "SM1-CTR") == 0) {
        return SGD_SM1_CTR;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetSM4AlgoId(const char *algoName) {
    if (strcmp(algoName, "SM4-ECB") == 0) {
        return SGD_SM4_ECB;
    } else if (strcmp(algoName, "SM4-CBC") == 0) {
        return SGD_SM4_CBC;
    } else if (strcmp(algoName, "SM4-CFB") == 0) {
        return SGD_SM4_CFB;
    } else if (strcmp(algoName, "SM4-OFB") == 0) {
        return SGD_SM4_OFB;
    } else if (strcmp(algoName, "SM4-CTR") == 0) {
        return SGD_SM4_CTR;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetSM7AlgoId(const char *algoName) {
    if (strcmp(algoName, "SM7-ECB") == 0) {
        return SGD_SM7_ECB;
    } else if (strcmp(algoName, "SM7-CBC") == 0) {
        return SGD_SM7_CBC;
    } else if (strcmp(algoName, "SM7-CFB") == 0) {
        return SGD_SM7_CFB;
    } else if (strcmp(algoName, "SM7-OFB") == 0) {
        return SGD_SM7_OFB;
    } else if (strcmp(algoName, "SM7-CTR") == 0) {
        return SGD_SM7_CTR;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetAESAlgoId(const char *algoName) {
    if (strcmp(algoName, "AES-ECB") == 0) {
        return SGD_AES_ECB;
    } else if (strcmp(algoName, "AES-CBC") == 0) {
        return SGD_AES_CBC;
    } else if (strcmp(algoName, "AES-CFB") == 0) {
        return SGD_AES_CFB;
    } else if (strcmp(algoName, "AES-OFB") == 0) {
        return SGD_AES_OFB;
    } else if (strcmp(algoName, "AES-CTR") == 0) {
        return SGD_AES_CTR;
    } else {
        return SDF_INVALID_VALUE;
    }
}

int SDF_StartsWith(const char* str1, const char* str2)
{
    if (str1 == NULL || str2 == NULL) {
        return 0;
    }
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    if (len1 > len2 || (len1 == 0 || len2 == 0)) {
        return 0;
    }
    const char *cur = str1;
    int i = 0;
    while (*cur != '\0') {
        if (*cur != str2[i]) {
            return 0;
        }
        cur++;
        i++;
    }
    return 1;
}

unsigned int SDF_GetSymmetricAlgoId(const char *algoName) {
    if (SDF_StartsWith("SM4", algoName)) {
        return SDF_GetSM4AlgoId(algoName);
    } else if (SDF_StartsWith("SM1", algoName)) {
        return SDF_GetSM1AlgoId(algoName);
    } else if (SDF_StartsWith("SM7", algoName)) {
        return SDF_GetSM7AlgoId(algoName);
    } else if (SDF_StartsWith("AES", algoName)) {
        return SDF_GetAESAlgoId(algoName);
    } else {
        return SDF_INVALID_VALUE;
    }
}


unsigned int SDF_GetAsymmetricPBKLen(unsigned int uiKeyType) {
    if (uiKeyType == SDF_ASYMMETRIC_KEY_TYPE_SM2) {
        return sizeof(ECCrefPublicKey_HW);
    } else if (uiKeyType == SDF_ASYMMETRIC_KEY_TYPE_RSA) {
        return sizeof(RSArefPublicKeyEx);
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetAsymmetricPRKLen(unsigned int uiKeyType) {
    if (uiKeyType == SDF_ASYMMETRIC_KEY_TYPE_SM2) {
        return sizeof(C_SM2Pairs);
    } else if (uiKeyType == SDF_ASYMMETRIC_KEY_TYPE_RSA) {
        return sizeof(RSArefPrivateKeyEx);
    } else {
        return SDF_INVALID_VALUE;
    }
}

KEKInfo* SDF_NewKEKInfo(JNIEnv *env, jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId) {
    jbyte *kekIdBytes = NULL;
    unsigned int kekIdLen;
    jbyte *regionIdBytes = NULL;
    unsigned int regionIdLen;
    jbyte *cdpIdBytes = NULL;
    unsigned int cdpIdLen;
    KEKInfo *uiKEKInfo = NULL;
    unsigned int kekInfoLen;

    kekInfoLen = sizeof(KEKInfo);
    uiKEKInfo = malloc(kekInfoLen);
    memset(uiKEKInfo, 0, kekInfoLen);
    if (!uiKEKInfo) {
        SDF_LOG_ERROR("malloc KEKInfo failed");
        goto cleanup;
    }

    if (kekId) {
        kekIdBytes = (*env)->GetByteArrayElements(env, kekId, NULL);
        kekIdLen = (*env)->GetArrayLength(env, kekId);
        memcpy(uiKEKInfo->KEKID, kekIdBytes, kekIdLen);
    }
    if (regionId) {
        regionIdBytes = (*env)->GetByteArrayElements(env, regionId, NULL);
        regionIdLen = (*env)->GetArrayLength(env, regionId);
        memcpy(uiKEKInfo->RegionID, regionIdBytes, regionIdLen);
    }
    if (cdpId) {
        cdpIdBytes = (*env)->GetByteArrayElements(env, cdpId, NULL);
        cdpIdLen = (*env)->GetArrayLength(env, cdpId);
        memcpy(uiKEKInfo->CdpID, cdpIdBytes, cdpIdLen);
    }

cleanup:
    if (kekIdBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, kekId, kekIdBytes, 0);
    }
    if (regionIdBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, regionId, regionIdBytes, 0);
    }
    if (cdpIdBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, cdpId, cdpIdBytes, 0);
    }
    return uiKEKInfo;
}

void SDF_ReleaseKEKInfo(KEKInfo *uiKEKInfo) {
    if (!uiKEKInfo) {
        return;
    }
    free(uiKEKInfo);
}


unsigned int SDF_GetECCrefPublicKeyLen() {
    return sizeof(ECCrefPublicKey_HW);
}

unsigned char *SDF_NewECCrefPublicKeyChars(JNIEnv *env, jbyteArray xArr, jbyteArray yArr, jint bits) {
    jbyte *x = NULL;
    int xLen;
    jbyte *y = NULL;
    int yLen;

    ECCrefPublicKey_HW *refPubLicKey = NULL;
    unsigned int uiPBKLen;

    x = (*env)->GetByteArrayElements(env, xArr, 0);
    xLen = (*env)->GetArrayLength(env, xArr);
    y = (*env)->GetByteArrayElements(env, yArr, 0);
    yLen = (*env)->GetArrayLength(env, yArr);

    uiPBKLen = SDF_GetECCrefPublicKeyLen();

    // ECCrefPublicKey_HW
    if ((refPubLicKey = malloc(uiPBKLen)) == NULL) {
        SDF_LOG_ERROR("malloc ECCrefPublicKey_HW failed");
        goto cleanup;
    }
    memset(refPubLicKey,0,uiPBKLen);
    refPubLicKey->bits = bits;
    memcpy(refPubLicKey->x, x, xLen);
    memcpy(refPubLicKey->y, y, yLen);

cleanup:
    if (x != NULL) {
        (*env)->ReleaseByteArrayElements(env, xArr, x, 0);
    }
    if (y != NULL) {
        (*env)->ReleaseByteArrayElements(env, yArr, y, 0);
    }
    return (unsigned char *) refPubLicKey;
}

void SDF_ReleaseECCrefPubicKeyChars(unsigned char *uiPublicKey) {
    if (uiPublicKey == NULL) {
        return;
    }
    free(uiPublicKey);
}


void SDF_Print_Chars(const char *attrName, unsigned char *p, unsigned int len) {
    printf("%s=", attrName);
    for (int i = 0; i < len; ++i) {
        printf("%d,", p[i]);
    }
    printf("\n");
}