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

#include "org_openeuler_sdf_wrapper_SDFSymmetricCipherNative.h"
#include "sdf_exception.h"
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "sdf.h"
#include "sdf_util.h"

static void FreeMemoryFromInit(JNIEnv* env, jbyteArray iv, jbyte* ivBytes, jbyteArray key, jbyte* keyBytes,
    int keyLength, jstring cipherType, const char* algo)
{
    if (ivBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, 0);
    }
    if (keyBytes != NULL) {
        memset(keyBytes, 0, keyLength);
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, 0);
    }
    if (algo != NULL) {
        (*env)->ReleaseStringUTFChars(env, cipherType, algo);
    }
}

static void FreeMemoryFromUpdate(unsigned char* in, unsigned char* aad, unsigned char* out)
{
    if (in != NULL) {
        free(in);
    }
    if (out != NULL) {
        free(out);
    }
    if (aad != NULL) {
        free(aad);
    }
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSymmetricCipherNative
 * Method:    nativeCipherInit
 * Signature: (JLjava/lang/String;Z[B[BZ)J
 */
JNIEXPORT jlong JNICALL Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherInit(JNIEnv *env, jclass cls,
  jlong sessionHandleAddr, jstring cipherAlgo, jboolean encrypt, jbyteArray keyArr, jbyteArray ivArr, jboolean padding)
{
    SGD_HANDLE sessionHandle = (SGD_HANDLE)sessionHandleAddr;
    SGD_HANDLE keyHandle = NULL;
    void* cipherHandle = NULL;

    jbyte* uiKey = NULL;
    jbyte* pucIv = NULL;
    int ivLength = 0;
    int keyLength = 0;
    const char* algoName = NULL;
    unsigned int uiAlgID = 0;
    SGD_RV rv;

    if (keyArr == NULL) {
        throwNullPointerException(env, "NativeCipherInit failed. keyArr is Null.");
        goto cleanup;
    }
    uiKey = (*env)->GetByteArrayElements(env, keyArr, NULL);
    keyLength = (*env)->GetArrayLength(env, keyArr);

    if (ivArr != NULL) {
        pucIv = (*env)->GetByteArrayElements(env, ivArr, NULL);
        ivLength = (*env)->GetArrayLength(env, ivArr);
    }

    algoName = (*env)->GetStringUTFChars(env, cipherAlgo, 0);
    uiAlgID = SDF_GetSymmetricAlgoId(algoName);
    if (uiAlgID == SDF_INVALID_VALUE) {
        throwIllegalArgumentException(env, "SDF_GetSymmetricAlgoId failed");
        goto cleanup;
    }

    // Import normal or encrypted key
    if ((rv = SDF_HW_ImportKey(sessionHandle, uiKey, keyLength, &keyHandle)) != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    // Apply for symmetric encryption context
    if ((rv = SDF_HW_MemoryCalloc(sessionHandle, SDF_CTX_TYPE_SYMMETRIC, &cipherHandle)) != 0) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    if (encrypt) {
        if ((rv = SDF_HW_SymmEncryptInit(sessionHandle, keyHandle, NULL, uiAlgID, pucIv, ivLength, padding ? 1 : 0, 0, cipherHandle)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    }else {
        if ((rv = SDF_HW_SymmDecryptInit(sessionHandle, keyHandle, NULL, uiAlgID, pucIv, ivLength, padding ? 1 : 0, 0, cipherHandle)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    }
    FreeMemoryFromInit(env, ivArr, pucIv, keyArr, uiKey, keyLength, cipherAlgo, algoName);
    return (jlong)cipherHandle;

cleanup:
    if (keyHandle != NULL) {
      SDF_DestroyKey(sessionHandle, keyHandle);
    }
    if (cipherHandle != NULL) {
        SDF_HW_MemoryFree(sessionHandle, 0, cipherHandle);
    }
    FreeMemoryFromInit(env, ivArr, pucIv, keyArr, uiKey, keyLength, cipherAlgo, algoName);
    return 0;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSymmetricCipherNative
 * Method:    nativeCipherUpdate
 * Signature: (JJ[BII[BIZ)I
 */
JNIEXPORT jint JNICALL Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherUpdate(JNIEnv *env, jclass cls,
  jlong sessionHandleAddr, jlong ctxAddress, jbyteArray inArr, jint inOfs, jint inLen, jbyteArray outArr, jint outOfs, jboolean encrypt)
{
    SGD_HANDLE sessionHandle = (SGD_HANDLE)sessionHandleAddr;
    void* cipherHandle = (void*)ctxAddress;

    unsigned char* in = NULL;
    unsigned char* out = NULL;
    unsigned char* aad = NULL;
    unsigned int outLen = 0;
    unsigned int bytesWritten = 0;
    SGD_RV rv;

    if (cipherHandle == NULL || inArr == NULL || outArr == NULL) {
        throwNullPointerException(env, "NativeCipherUpdate failed. The parameter cannot be empty.");
        goto cleanup;
    }

    if ((in = (unsigned char*)malloc(inLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherUpdate failed. Unable to allocate in 'in' buffer");
        goto cleanup;
    }
    memset(in, 0, inLen);
    (*env)->GetByteArrayRegion(env, inArr, inOfs, inLen, (jbyte*)in);

    outLen = (*env)->GetArrayLength(env, outArr) - outOfs;
    if ((out = (unsigned char*)malloc(outLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherUpdate failed. Unable to allocate in 'out' buffer");
        goto cleanup;
    }
    memset(out, 0, outLen);

    if (encrypt) {
        if ((rv = SDF_HW_SymmEncryptUpdate(sessionHandle, in, inLen, out, &bytesWritten, cipherHandle)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    }else {
        if ((rv = SDF_HW_SymmDecryptUpdate(sessionHandle, in, inLen, out, &bytesWritten, cipherHandle)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    }
    (*env)->SetByteArrayRegion(env, outArr, outOfs, bytesWritten, (jbyte*)out);
cleanup:
    FreeMemoryFromUpdate(in, aad, out);
    return bytesWritten;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSymmetricCipherNative
 * Method:    nativeCipherFinal
 * Signature: (JJ[BIZ)I
 */
JNIEXPORT jint JNICALL Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherFinal(JNIEnv *env, jclass cls,
  jlong sessionHandleAddr, jlong ctxAddress, jbyteArray inArr, jint inOfs, jint inLen, jbyteArray outArr, jint outOfs, jboolean encrypt)
{
    SGD_HANDLE sessionHandle = (SGD_HANDLE)sessionHandleAddr;
    void* cipherHandle = (void*) ctxAddress;
    unsigned char* in = NULL;
    unsigned char* out = NULL;
    unsigned int outLen = 0;
    unsigned  int bytesWritten = 0;
    SGD_RV rv = 0;

    if (cipherHandle == NULL || outArr == NULL || inArr == NULL) {
        throwNullPointerException(env, "NativeCipherFinal failed. The parameter cannot be empty.");
        goto cleanup;
    }
    if ((in = (unsigned char*)malloc(inLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherUpdate failed. Unable to allocate in 'in' buffer");
        goto cleanup;
    }
    memset(in, 0, inLen);
    (*env)->GetByteArrayRegion(env, inArr, inOfs, inLen, (jbyte*)in);

    outLen = (*env)->GetArrayLength(env, outArr) - outOfs;
    if ((out = (unsigned char*)malloc(outLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeCipherFinal failed. Unable to allocate in 'out' buffer");
        goto cleanup;
    }
    memset(out, 0, outLen);

    if (encrypt) {
        if ((rv = SDF_HW_SymmEncryptFinal(sessionHandle, in, inLen, out, &bytesWritten, cipherHandle)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    }else {
        if ((rv = SDF_HW_SymmDecryptFinal(sessionHandle,in,inLen, out, &bytesWritten, cipherHandle)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    }
    (*env)->SetByteArrayRegion(env, outArr, outOfs, bytesWritten, (jbyte*)out);
cleanup:
    if (in != NULL) {
        free(in);
    }
    if (out != NULL) {
        free(out);
    }
    return bytesWritten;
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFSymmetricCipherNative
 * Method:    nativeCipherCtxFree
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_org_openeuler_sdf_wrapper_SDFSymmetricCipherNative_nativeCipherCtxFree(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jlong ctxAddress) {
    if (sessionHandleAddr == 0 || ctxAddress == 0) {
        return;
    }
    SGD_HANDLE sessionHandle = (SGD_HANDLE *) sessionHandleAddr;
    void *cipherHandle = (void *) ctxAddress;
    // free cipherHandle and keyHandle ( uiType | HW_KEYDESTROY_MASK)
    unsigned uiType = SDF_CTX_TYPE_SYMMETRIC | HW_KEYDESTROY_MASK;
    SGD_RV rv;

    if ((rv = SDF_HW_MemoryFree(sessionHandle, uiType, cipherHandle)) != SDR_OK) {
        throwSDFException(env, rv);
    }
}
