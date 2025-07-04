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
#include "cryptocard/crypto_sdk_pf.h"

#include "sdf_util.h"

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFInternalNative_encryptKey(JNIEnv *env, jclass clazz,
        jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId, jbyteArray pin, jint uiType, jbyteArray plainKeyArr) {
    unsigned int algId = ALG_SM4;
    unsigned int ivLen = 16;
    unsigned char iv[ivLen];
    void *dekParams = NULL;
    unsigned int outKeyType = uiType;
    unsigned char *plainKeyTmp = NULL;
    unsigned char *plainKey = NULL;
    unsigned int plainKeyLen;
    unsigned int cipherKeyLen = 10240;
    unsigned char cipherKey[cipherKeyLen];
    jbyteArray encKeyArr = NULL;
    SGD_RV rv;

    plainKey = (*env)->GetByteArrayElements(env, plainKeyArr, NULL);
    plainKeyLen = (*env)->GetArrayLength(env, plainKeyArr);
    if (outKeyType == DATA_KEY_SM2) {
        int sm2PriKeyLen = sizeof(SM2PrivateKey);
        plainKeyTmp = malloc(sm2PriKeyLen);
        SM2PrivateKey *sm2PriKey = (SM2PrivateKey *) plainKeyTmp;
        sm2PriKey->bits = 256;
        memcpy(sm2PriKey->D, plainKey, plainKeyLen);
        plainKeyLen = sm2PriKeyLen;
    } else {
        plainKeyTmp = malloc(plainKeyLen);
        memcpy(plainKeyTmp, plainKey, plainKeyLen);
    }
    plainKeyLen = plainKeyLen << 3; // key len in bits

    if (!(dekParams = SDF_CreateDEKParams(env, kekId, regionId, cdpId, pin))) {
        goto cleanup;
    }

    if ((rv = CDM_GenRandom(ivLen, iv)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_GenRandom");
        goto cleanup;
    }

    if ((rv = CDM_EncryptSecretKeyWithoutPlaintext(
            algId,
            iv,
            ivLen,
            outKeyType,
            dekParams,
            plainKeyTmp,
            plainKeyLen,
            cipherKey,
            &cipherKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_EncryptSecretKeyWithoutPlaintext");
        goto cleanup;
    }

    encKeyArr = (*env)->NewByteArray(env, cipherKeyLen);
    (*env)->SetByteArrayRegion(env, encKeyArr, 0, cipherKeyLen, cipherKey);

cleanup:
    SDF_FreeDEKParams(env, dekParams);
    if (plainKey) {
        (*env)->ReleaseByteArrayElements(env, plainKeyArr, plainKey, 0);
    }
    if (plainKeyTmp) {
        free(plainKeyTmp);
    }
    return encKeyArr;
}
