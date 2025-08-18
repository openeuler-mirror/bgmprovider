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
#include "cryptocard/crypto_sdk_struct.h"
#include "cryptocard/crypto_sdk_pf.h"
#include "cryptocard/errno.h"

#include "sdf_util.h"
#include "sdf_log.h"


enum SDF_SM2_PUBLIC_KEY_PARAMS_IDX {
    SDF_SM2_PUBLIC_KEY_X_IDX = 0,
    SDF_SM2_PUBLIC_KEY_Y_IDX = 1,
    SDF_SM2_PUBLIC_KEY_BITS_IDX = 2,
} ;

enum SDF_SM2_CIPHER_IDX {
    SDF_SM2_CIPHER_C1_X_IDX = 0,
    SDF_SM2_CIPHER_C1_Y_IDX = 1,
    SDF_SM2_CIPHER_C2_IDX = 2,
    SDF_SM2_CIPHER_C3_IDX = 3,
    SDF_SM2_CIPHER_PARAMS_LEN = 4
};


void *SDF_MALLOC(size_t num) {
    return calloc(num, sizeof(char));
}

void *SDF_Free(void *ptr) {
    free(ptr);
}


/*jbyteArray SDF_GetByteArrayFromCharArr(JNIEnv* env, const char* charArr, int arrLen)
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
    unsigned int PBKLen = SDF_GetAsymmetricPBKLen(DATA_KEY_SM2);

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
}*/

unsigned int SDF_GetDigestAlgoId(const char *algoName) {
    if (strcmp(algoName, "SM3") == 0) {
        return ALG_SM3;
    } else if (strcmp(algoName, "SHA-256") == 0) {
        return ALG_SHA256;
    } else if (strcmp(algoName, "SHA-384") == 0) {
        return ALG_SHA384;
    } else if (strcmp(algoName, "SHA-512") == 0) {
        return ALG_SHA512;
    } else if (strcmp(algoName, "SHA-1") == 0) {
        return ALG_SHA1;
    } else if (strcmp(algoName, "SHA-224") == 0) {
        return ALG_SHA224;
    } else if (strcmp(algoName, "MD5") == 0) {
        return ALG_MD5;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetSymmetricModeType(const char *modeName) {
    if (strcmp("ECB", modeName) == 0) {
        return ALG_MODE_ECB;
    } else if (strcmp("CBC", modeName) == 0) {
        return ALG_MODE_CBC;
    } else if (strcmp("CFB", modeName) == 0) {
        return ALG_MODE_CFB;
    } else if (strcmp("OFB", modeName) == 0) {
        return ALG_MODE_OFB;
    } else if (strcmp("GCM", modeName) == 0) {
        return ALG_MODE_GCM;
    } else if (strcmp("CCM", modeName) == 0) {
        return ALG_MODE_CCM;
    } else if (strcmp("XTS", modeName) == 0) {
        return ALG_MODE_XTS;
    } else if (strcmp("CTR", modeName) == 0) {
        return ALG_MODE_CTR;
    } else {
        return SDF_INVALID_VALUE;
    }
}


unsigned int SDF_GetAsymmetricPBKLen(unsigned int uiKeyType) {
    if (uiKeyType == DATA_KEY_SM2) {
        return SDF_SM2_ENC_PUB_KEY_SIZE;
    } else if (uiKeyType == DATA_KEY_RSA) {
        return SDF_INVALID_VALUE;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetAsymmetricPRKLen(unsigned int uiKeyType) {
    if (uiKeyType == DATA_KEY_SM2) {
        return SDF_SM2_ENC_PRI_KEY_SIZE;
    } else if (uiKeyType == DATA_KEY_RSA) {
        return SDF_INVALID_VALUE;
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
    if (!uiKEKInfo) {
        SDF_LOG_ERROR("malloc KEKInfo failed");
        goto cleanup;
    }
    memset(uiKEKInfo, 0, kekInfoLen);

    if (kekId) {
        kekIdBytes = (*env)->GetByteArrayElements(env, kekId, NULL);
        kekIdLen = (*env)->GetArrayLength(env, kekId);
        memcpy(uiKEKInfo->kekId, kekIdBytes, kekIdLen);
    }
    if (regionId) {
        regionIdBytes = (*env)->GetByteArrayElements(env, regionId, NULL);
        regionIdLen = (*env)->GetArrayLength(env, regionId);
        memcpy(uiKEKInfo->regionId, regionIdBytes, regionIdLen);
    }
    if (cdpId) {
        cdpIdBytes = (*env)->GetByteArrayElements(env, cdpId, NULL);
        cdpIdLen = (*env)->GetArrayLength(env, cdpId);
        memcpy(uiKEKInfo->cdpId, cdpIdBytes, cdpIdLen);
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

void *SDF_CreateDEKParams(JNIEnv *env, jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId, jbyteArray pin) {
    KEKInfo *kekInfo = NULL;
    jbyte *pinBytes = NULL;
    unsigned int pinLen = 0;
    void *dekParams = NULL;
    SGD_RV rv;

    kekInfo = SDF_NewKEKInfo(env, kekId, regionId, cdpId);
    if (!kekInfo) {
        throwSDFRuntimeException(env, "SDF_NewKEKInfo failed");
        goto cleanup;
    }
    if (pin) {
        pinBytes = (*env)->GetByteArrayElements(env, pin, NULL);
        pinLen = (*env)->GetArrayLength(env, pin);
    }

    if ((rv = CDM_CreateDEKParams(kekInfo, pinBytes, pinLen, &dekParams)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_CreateDEKParams");
        goto cleanup;
    }

cleanup:
    if (pinBytes) {
        (*env)->ReleaseByteArrayElements(env, pin, pinBytes, 0);
    }
    SDF_ReleaseKEKInfo(kekInfo);
    return dekParams;
}

void SDF_FreeDEKParams(JNIEnv *env, void *dekParams) {
    if (!dekParams) {
        return;
    }
    SGD_RV rv;
    if ((rv = CDM_FreeDEKParams(dekParams)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_FreeDEKParams");
        return;
    }
}


unsigned int SDF_GetSM2PublicKeyLen() {
    return SDF_GetAsymmetricPBKLen(DATA_KEY_SM2);
}

unsigned char *SDF_CreateSM2PublicKey(JNIEnv *env, jobjectArray pubKeyArr, unsigned int *pubKeyLen) {
    jbyteArray xArr = NULL;
    unsigned char *x = NULL;
    unsigned int xLen;
    jbyteArray yArr = NULL;
    unsigned char *y = NULL;
    unsigned int yLen;
    unsigned int bitsLen;

    char *pubKey = NULL;
    SGD_RV rv;

    xArr = (*env)->GetObjectArrayElement(env, pubKeyArr, SDF_SM2_PUBLIC_KEY_X_IDX);
    x = (*env)->GetByteArrayElements(env, xArr, 0);
    xLen = (*env)->GetArrayLength(env, xArr);

    yArr = (*env)->GetObjectArrayElement(env, pubKeyArr, SDF_SM2_PUBLIC_KEY_Y_IDX);
    y = (*env)->GetByteArrayElements(env, yArr, 0);
    yLen = (*env)->GetArrayLength(env, yArr);

    bitsLen = xLen << 3;
    if ((rv = CDM_SetSM2PubKeyElements(x, xLen, y, yLen, bitsLen, pubKey, pubKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_SetSM2PubKeyElements");
        goto cleanup;
    }
    if ((pubKey = malloc( *pubKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc pubKey failed");
        goto cleanup;
    }

    if ((rv = CDM_SetSM2PubKeyElements(x, xLen, y, yLen, bitsLen, pubKey, pubKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_SetSM2PubKeyElements");
        goto cleanup;
    }

cleanup:
    if (x != NULL) {
        (*env)->ReleaseByteArrayElements(env, xArr, x, 0);
    }
    if (y != NULL) {
        (*env)->ReleaseByteArrayElements(env, yArr, y, 0);
    }
    return pubKey;
}

void SDF_FreeSM2PublicKey(unsigned char *pubKey) {
    if (pubKey == NULL) {
        return;
    }
    free(pubKey);
}

void *SDF_CreateSM2PriKeyHandle(JNIEnv *env, jbyteArray priKeyArr, jbyteArray pinArr) {
    void *keyHandle = NULL;
    const char *priKey = NULL;
    unsigned int priKeyLen;
    jbyte *pin = NULL;
    int pinLen = 0;
    SGD_RV rv;
    // pin
    if (pinArr != NULL) {
        pin = (*env)->GetByteArrayElements(env, pinArr, NULL);
        pinLen = (*env)->GetArrayLength(env, pinArr);
    }
    priKeyLen = (*env)->GetArrayLength(env, priKeyArr);
    if ((priKey = malloc(priKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc priKey failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, priKeyArr, 0, priKeyLen, priKey);
    if ((rv = CDM_ImportKeyHandle(priKey, priKeyLen, pin, pinLen, &keyHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_ImportKeyHandle");
        goto cleanup;
    }

cleanup:
    if (priKey) {
        free(priKey);
    }
    if (pin != NULL) {
        (*env)->ReleaseByteArrayElements(env, pinArr, pin, 0);
    }
    return keyHandle;
}

void SDF_FreeSM2PriKeyHandle(void *keyHandle) {
    if (keyHandle == NULL) {
        return;
    }
    CDM_DestroyKeyHandle(keyHandle);
}

// SM2Cipher to jobjectArray
jobjectArray SDF_SM2CipherToObjectArray(JNIEnv *env, SM2Cipher *sm2Cipher) {
    jobjectArray cipherParams = NULL;
    jclass byteArrayClass = NULL;
    jbyteArray c1xArr;
    jbyteArray c1yArr;
    jbyteArray c2Arr;
    jbyteArray c3Arr;

    // cipherParams
    byteArrayClass = (*env)->FindClass(env, "[B");
    cipherParams = (*env)->NewObjectArray(env, SDF_SM2_CIPHER_PARAMS_LEN, byteArrayClass, NULL);

    // C1 x
    c1xArr = (*env)->NewByteArray(env, SM2_KEY_BUF_LEN);
    (*env)->SetByteArrayRegion(env, c1xArr, 0, SM2_KEY_BUF_LEN, (jbyte *) sm2Cipher->x);
    (*env)->SetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C1_X_IDX, c1xArr);

    // C1 y
    c1yArr = (*env)->NewByteArray(env, SM2_KEY_BUF_LEN);
    (*env)->SetByteArrayRegion(env, c1yArr, 0, SM2_KEY_BUF_LEN, (jbyte *) sm2Cipher->y);
    (*env)->SetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C1_Y_IDX, c1yArr);

    // C2
    c2Arr = (*env)->NewByteArray(env, sm2Cipher->L);
    (*env)->SetByteArrayRegion(env, c2Arr, 0, sm2Cipher->L, (jbyte *) sm2Cipher->C);
    (*env)->SetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C2_IDX, c2Arr);

    // C3
    c3Arr = (*env)->NewByteArray(env, SM2_KEY_BUF_LEN);
    (*env)->SetByteArrayRegion(env, c3Arr, 0, SM2_KEY_BUF_LEN, (jbyte *) sm2Cipher->M);
    (*env)->SetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C3_IDX, c3Arr);

cleanup:
    if (c3Arr) {
        (*env)->DeleteLocalRef(env, c3Arr);
    }
    if (c2Arr) {
        (*env)->DeleteLocalRef(env, c2Arr);
    }
    if (c1yArr) {
        (*env)->DeleteLocalRef(env, c1yArr);
    }
    if (c1xArr) {
        (*env)->DeleteLocalRef(env, c1xArr);
    }
    if (byteArrayClass) {
        (*env)->DeleteLocalRef(env, byteArrayClass);
    }

    return cipherParams;
}

// jobjectArray to SM2Cipher
SM2Cipher * SDF_ObjectArrayToSM2Cipher(JNIEnv *env, jobjectArray cipherParams, unsigned int* encDataLen) {
    jbyteArray c1xArr = NULL;
    jsize c1xLen = 0;
    jbyteArray c1yArr = NULL;
    jsize c1yLen = 0;
    jbyteArray c2Arr = NULL;
    jsize c2Len = 0;
    jbyteArray c3Arr = NULL;
    jsize c3Len = 0;

    c1xArr = (*env)->GetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C1_X_IDX);
    c1xLen = (*env)->GetArrayLength(env, c1xArr);

    c1yArr = (*env)->GetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C1_Y_IDX);
    c1yLen = (*env)->GetArrayLength(env, c1yArr);

    c2Arr = (*env)->GetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C2_IDX);
    c2Len = (*env)->GetArrayLength(env, c2Arr);

    c3Arr = (*env)->GetObjectArrayElement(env, cipherParams, SDF_SM2_CIPHER_C3_IDX);
    c3Len = (*env)->GetArrayLength(env, c3Arr);

    SM2Cipher *sm2Cipher = NULL;
    *encDataLen = c1xLen + c1yLen + c3Len + c2Len + sizeof(int);
    if (!(sm2Cipher = malloc(*encDataLen))) {
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, c1xArr, 0, c1xLen, (jbyte*) sm2Cipher->x);
    (*env)->GetByteArrayRegion(env, c1yArr, 0, c1yLen, (jbyte*) sm2Cipher->y);
    sm2Cipher->L = c2Len;
    (*env)->GetByteArrayRegion(env, c2Arr, 0, c2Len, (jbyte*) sm2Cipher->C);
    (*env)->GetByteArrayRegion(env, c3Arr, 0, c3Len, (jbyte*) sm2Cipher->M);
cleanup:
    if (c3Arr) {
        (*env)->DeleteLocalRef(env, c3Arr);
    }
    if (c2Arr) {
        (*env)->DeleteLocalRef(env, c2Arr);
    }
    if (c1yArr) {
        (*env)->DeleteLocalRef(env, c1yArr);
    }
    if (c1xArr) {
        (*env)->DeleteLocalRef(env, c1xArr);
    }
    return sm2Cipher;
}


void SDF_Print_Chars(const char *attrName, unsigned char *p, unsigned int len) {
    printf("%s=", attrName);
    for (int i = 0; i < len; ++i) {
        printf("%d,", p[i]);
    }
    printf("\n");
}

unsigned int SDF_GetAsymmetricKeyType(const char *algoName) {
    if (strcasecmp("SM2", algoName) == 0) {
        return DATA_KEY_SM2;
    } else if (strcasecmp("RSA", algoName) == 0) {
        return DATA_KEY_RSA;
    } else if (strcasecmp("ECC", algoName) == 0) {
        return DATA_KEY_ECC;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetHmacKeyType(const char *algoName) {
    if (strcasecmp("HmacSM3", algoName) == 0 || strcasecmp("SM3", algoName) == 0) {
        return DATA_KEY_HMAC_SM3;
    } else if (strcasecmp("HmacSHA1", algoName) == 0 || strcasecmp("SHA1", algoName) == 0) {
        return DATA_KEY_HMAC_SHA1;
    } else if (strcasecmp("HmacSHA224", algoName) == 0 || strcasecmp("SHA224", algoName) == 0) {
        return DATA_KEY_HMAC_SHA224;
    } else if (strcasecmp("HmacSHA256", algoName) == 0 || strcasecmp("SHA256", algoName) == 0) {
        return DATA_KEY_HMAC_SHA256;
    } else if (strcasecmp("HmacSHA384", algoName) == 0 || strcasecmp("SHA384", algoName) == 0) {
        return DATA_KEY_HMAC_SHA384;
    } else if (strcasecmp("HmacSHA512", algoName) == 0 || strcasecmp("SHA512", algoName) == 0) {
        return DATA_KEY_HMAC_SHA512;
    } else {
        return SDF_INVALID_VALUE;
    }
}

unsigned int SDF_GetSymmetricKeyType(const char *algoName) {
    if (strcasecmp("SM4", algoName) == 0) {
        return DATA_KEY_SM4;
    } else if (strcasecmp("SM1", algoName) == 0) {
        return DATA_KEY_SM1;
    } else if (strcasecmp("SM7", algoName) == 0) {
        return DATA_KEY_SM7;
    } else if (strcasecmp("AES", algoName) == 0) {
        return DATA_KEY_AES;
    } else if (strcasecmp("3DES", algoName) == 0) {
        return DATA_KEY_3DES;
    } else {
        return SDF_INVALID_VALUE;
    }
}

void *SDF_CreateSM9PriKeyHandle(JNIEnv *env, jbyteArray priKeyArr) {
    void *keyHandle = NULL;
    const char *priKey = NULL;
    unsigned int priKeyLen;
    SGD_RV rv;

    priKeyLen = (*env)->GetArrayLength(env, priKeyArr);
    if ((priKey = malloc(priKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc priKey failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, priKeyArr, 0, priKeyLen, priKey);
    if ((rv = CDM_ImportKeyHandle(priKey, priKeyLen, NULL, 0, &keyHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_ImportKeyHandle");
        goto cleanup;
    }

cleanup:
    if (priKey) {
        free(priKey);
    }
    return keyHandle;
}

void SDF_FreeSM9PriKeyHandle(void *keyHandle) {
    if (keyHandle == NULL) {
        return;
    }
    CDM_DestroyKeyHandle(keyHandle);
}