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

#include "org_openeuler_sdf_wrapper_SDFKeyGeneratorNative.h"
#include "sdf_exception.h"
#include "sdf.h"
#include "sdf_util.h"

#define DEFAULT_ENC_KEY_ALG_ID SGD_SM4_ECB

jbyteArray generateSecretKey(JNIEnv *env, jlong sessionHandleAddr, jbyteArray kekIdArr, jbyteArray regionIdArr,
        jbyteArray cdpIdArr, jbyteArray PINArr, jint keySize, jboolean isHmac) {
    SGD_HANDLE sessionHandle = (SGD_HANDLE) sessionHandleAddr;
    jbyte *PINBytes = NULL;
    int PinLen = 0;
    unsigned int encKeyLen = isHmac ? HMAC_KEY_LEN : SYSCKEY_LEN;
    unsigned char encKey[encKeyLen];

    KEKInfo *kekInfo = NULL;

    jbyteArray encKeyArr = NULL;
    SGD_RV rv;

    kekInfo = SDF_NewKEKInfo(env, kekIdArr, regionIdArr, cdpIdArr);

    if (PINArr != NULL) {
        PINBytes = (*env)->GetByteArrayElements(env, PINArr, NULL);
        PinLen = (*env)->GetArrayLength(env, PINArr);
    }

    if (isHmac) {
        if ((rv = SDF_HW_CreateDataKeyWithoutPlaintext_HMAC(sessionHandle, DEFAULT_ENC_KEY_ALG_ID, NULL, 0, PINBytes,
                PinLen, kekInfo, keySize, encKey, &encKeyLen)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    } else {
        if ((rv = SDF_HW_CreateDataKeyWithoutPlaintext(sessionHandle, DEFAULT_ENC_KEY_ALG_ID, NULL, 0, PINBytes,
                PinLen, kekInfo, keySize, encKey, &encKeyLen)) != 0) {
            throwSDFException(env, rv);
            goto cleanup;
        }
    }
    encKeyArr = (*env)->NewByteArray(env, encKeyLen);
    (*env)->SetByteArrayRegion(env, encKeyArr, 0, encKeyLen, (jbyte *) encKey);

cleanup:
    if (kekInfo != NULL) {
        SDF_ReleaseKEKInfo(kekInfo);
    }
    if (PINBytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, PINArr, PINBytes, 0);
    }
    return encKeyArr;
}


JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFKeyGeneratorNative_nativeGenerateSecretKey (
        JNIEnv *env, jclass cls, jlong sessionHandleAddr, jbyteArray kekIdArr, jbyteArray regionIdArr,
        jbyteArray cdpIdArr, jbyteArray PINArr, jint keySize, jboolean isHmac) {
    return generateSecretKey(env, sessionHandleAddr, kekIdArr, regionIdArr, cdpIdArr, PINArr, keySize, isHmac);
}


