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
#include "cryptocard/errno.h"
#include "cryptocard/crypto_sdk_vf.h"

#include "org_openeuler_sdf_wrapper_SDFSymmetricCipherNative.h"
#include "sdf_exception.h"
#include "sdf_util.h"

static void FreeMemoryFromInit(JNIEnv *env, jbyteArray ivArr, jbyte *iv, jbyteArray keyArr, jbyte *key,
        int keyLength, jstring mode, const char *modeName) {
    if (iv != NULL) {
        (*env)->ReleaseByteArrayElements(env, ivArr, iv, 0);
    }
    if (key != NULL) {
        memset(key, 0, keyLength);
        (*env)->ReleaseByteArrayElements(env, keyArr, key, 0);
    }
    if (modeName != NULL) {
        (*env)->ReleaseStringUTFChars(env, mode, modeName);
    }
}

JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherInit(JNIEnv *env,
        jclass cls, jint keyType, jstring mode, jboolean isPadding, jbyteArray keyArr, jbyteArray ivArr,
        jbyteArray tagArr, jboolean encrypt) {
    void *keyHandle = NULL;
    void *sysCipher = NULL;
    int ctxType = CTX_TYPE_SYMM;

    jbyte *key = NULL;
    int keyLen = 0;
    jbyte *iv = NULL;
    int ivLen = 0;
    unsigned char *aad = NULL;
    int aadLen = 16;
    unsigned char *tag = NULL;
    int tagLen = 16;
    int dataUnitLen = 0;
    const char *modeName = NULL;
    unsigned int modeType;
    int padding;

    SGD_RV rv;

    // key
    key = (*env)->GetByteArrayElements(env, keyArr, NULL);
    keyLen = (*env)->GetArrayLength(env, keyArr);

    // iv
    if (ivArr != NULL) {
        iv = (*env)->GetByteArrayElements(env, ivArr, NULL);
        ivLen = (*env)->GetArrayLength(env, ivArr);
    }
    if ((aad = (unsigned char *) malloc(aadLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc aad failed.");
        goto cleanup;
    }
    // encrypt and decrypt should have same aad
    memset(aad, 1, aadLen);
    if (tagArr != NULL) {
        tag = (*env)->GetByteArrayElements(env, tagArr, NULL);
    }

    // mode
    modeName = (*env)->GetStringUTFChars(env, mode, 0);
    modeType = SDF_GetSymmetricModeType(modeName);
    if (modeType == SDF_INVALID_VALUE) {
        throwIllegalArgumentException(env, "SDF_GetSymmetricAlgoId failed");
        goto cleanup;
    }
    padding = isPadding ? PAD_PKCS7 : PAD_NO;

    // Import normal or encrypted key
    if ((rv = CDM_ImportKeyHandle(key, keyLen, NULL, 0, &keyHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_ImportKeyHandle");
        goto cleanup;
    }
    // Apply for symmetric encryption context
    if ((rv = CDM_MemoryCalloc(ctxType, &sysCipher)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryCalloc");
        goto cleanup;
    }
    if (encrypt) {
        if ((rv = CDM_SymmEncryptInit(keyHandle, keyType, modeType, iv, ivLen, padding, aad, aadLen,
                tagLen, dataUnitLen, sysCipher)) != SDR_OK) {
            throwSDFException(env, rv, "CDM_SymmEncryptInit");
            goto cleanup;
        }
    } else {
        if ((rv = CDM_SymmDecryptInit(keyHandle, keyType, modeType, iv, ivLen, padding, aad, aadLen,
                tag, tagLen, dataUnitLen, sysCipher)) != SDR_OK) {
            throwSDFException(env, rv, "CDM_SymmDecryptInit");
            goto cleanup;
        }
    }

    FreeMemoryFromInit(env, ivArr, iv, keyArr, key, keyLen, mode, modeName);
    return (jlong) sysCipher;

cleanup:
    if (keyHandle) {
        CDM_DestroyKeyHandle(keyHandle);
    }
    if (sysCipher) {
        CDM_MemoryFree(ctxType, sysCipher);
    }
    if (aad != NULL) {
        free(aad);
    }
    if (tag != NULL) {
        (*env)->ReleaseByteArrayElements(env, tagArr, tag, 0);
    }
    FreeMemoryFromInit(env, ivArr, iv, keyArr, key, keyLen, mode, modeName);
    return 0;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSymmetricCipherNative
 * Method:    nativeCipherUpdate
 * Signature: (JJ[BII[BIZ)I
 */
JNIEXPORT jint JNICALL Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherUpdate(JNIEnv *env,
        jclass cls, jlong ctxAddress, jbyteArray inArr, jint inOfs, jint inLen, jbyteArray outArr, jint outOfs,
        jboolean encrypt) {
    void *cipherHandle = (void *) ctxAddress;
    unsigned char *in = NULL;
    unsigned char *out = NULL;
    unsigned char *aad = NULL;
    unsigned int outLen = 0;
    SGD_RV rv;

    if (cipherHandle == NULL || inArr == NULL || outArr == NULL) {
        throwNullPointerException(env, "NativeCipherUpdate failed. The parameter cannot be empty.");
        goto cleanup;
    }

    if ((in = (unsigned char *) malloc(inLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherUpdate failed. Unable to allocate in 'in' buffer");
        goto cleanup;
    }
    memset(in, 0, inLen);
    (*env)->GetByteArrayRegion(env, inArr, inOfs, inLen, (jbyte *) in);

    outLen = (*env)->GetArrayLength(env, outArr);
    outLen = outLen - outOfs;
    if ((out = (unsigned char *) malloc(outLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherUpdate failed. Unable to allocate in 'out' buffer");
        goto cleanup;
    }
    memset(out, 0, outLen);

    if (encrypt) {
        if ((rv = CDM_SymmEncryptUpdate(in, inLen, cipherHandle, out, &outLen)) != SDR_OK) {
            throwSDFException(env, rv, "CDM_SymmEncryptUpdate");
            goto cleanup;
        }
    } else {
        if ((rv = CDM_SymmDecryptUpdate(in, inLen, cipherHandle, out, &outLen)) != SDR_OK) {
            throwSDFException(env, rv, "CDM_SymmDecryptUpdate");
            goto cleanup;
        }
    }
    (*env)->SetByteArrayRegion(env, outArr, outOfs, outLen, (jbyte *) out);
cleanup:
    if (in != NULL) {
        free(in);
    }
    if (out != NULL) {
        free(out);
    }
    if (aad != NULL) {
        free(aad);
    }
    return outLen;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSymmetricCipherNative
 * Method:    nativeCipherFinal
 * Signature: (JJ[BIZ)I
 */
JNIEXPORT jint JNICALL
Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherFinal(JNIEnv *env, jclass cls,
        jlong ctxAddress, jbyteArray inArr, jint inOfs, jint inLen, jbyteArray tagArr,
        jbyteArray outArr, jint outOfs, jboolean encrypt) {
    void* cipherHandle = (void *) ctxAddress;
    unsigned char *in = NULL;
    unsigned char *out = NULL;
    unsigned int outLen = 0;
    unsigned char *tag = NULL;
    int tagLen = 16;
    SGD_RV rv;

    if (cipherHandle == NULL || outArr == NULL || inArr == NULL) {
        throwNullPointerException(env, "NativeCipherFinal failed. The parameter cannot be empty.");
        goto cleanup;
    }
    if ((in = (unsigned char *) malloc(inLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherFinal failed. Unable to allocate in 'in' buffer");
        goto cleanup;
    }
    memset(in, 0, inLen);
    (*env)->GetByteArrayRegion(env, inArr, inOfs, inLen, (jbyte *) in);

    outLen = (*env)->GetArrayLength(env, outArr);
    outLen = outLen - outOfs;
    if ((out = (unsigned char *) malloc(outLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherFinal failed. Unable to allocate in 'out' buffer");
        goto cleanup;
    }
    memset(out, 0, outLen);

    if (encrypt) {
        if ((tag = (unsigned char *) malloc(tagLen)) == NULL) {
            throwOutOfMemoryError(env, "NativeCipherFinal failed. Unable to allocate in 'tag' buffer");
            goto cleanup;
        }
        if ((rv = CDM_SymmEncryptFinal(in, inLen, cipherHandle, out, &outLen, tag)) != SDR_OK) {
            throwSDFException(env, rv, "CDM_SymmEncryptFinal");
            goto cleanup;
        }
        if (tagArr != NULL) {
            (*env)->SetByteArrayRegion(env, tagArr, 0, tagLen, (jbyte *) tag);
        }
    } else {
        if ((rv = CDM_SymmDecryptFinal(cipherHandle, in, inLen, out, &outLen)) != SDR_OK) {
            throwSDFException(env, rv, "CDM_SymmDecryptFinal");
            goto cleanup;
        }
    }
    (*env)->SetByteArrayRegion(env, outArr, outOfs, outLen, (jbyte *) out);
cleanup:
    if (in != NULL) {
        free(in);
    }
    if (out != NULL) {
        free(out);
    }
    if (tag != NULL) {
        free(tag);
    }
    return outLen;
}

JNIEXPORT void JNICALL Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherCtxFree(JNIEnv *env,
        jclass cls, jlong ctxAddress) {
    if (ctxAddress == 0) {
        return;
    }
    void *cipherHandle = (void *) ctxAddress;
    // free cipherHandle and keyHandle
    unsigned uiType = CTX_TYPE_SYMM;
    SGD_RV rv;

    if ((rv = CDM_MemoryFree(uiType, cipherHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_MemoryFree");
        return;
    }
}
