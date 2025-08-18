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

#include "cryptocard/crypto_sdk_vf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFSM2KeyAgreementNative.h"
#include "sdf_util.h"

unsigned char *SDF_NewIDChars(JNIEnv *env, jbyteArray idArr) {
    return (unsigned char *) (*env)->GetByteArrayElements(env, idArr, 0);
}

unsigned int SDF_GetIDLen(JNIEnv *env, jbyteArray idArr) {
    return (*env)->GetArrayLength(env, idArr);
}

void SDF_ReleaseIDChars(JNIEnv *env, jbyteArray idArr, unsigned char *idBytes) {
    if (idBytes) {
        (*env)->ReleaseByteArrayElements(env, idArr, (jbyte *) idBytes, 0);
    }
}

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFSM2KeyAgreementNative_generateSharedSecret(
        JNIEnv *env, jclass cls, jbyteArray localIdArr, jbyteArray localCipherPriKeyArr, jobjectArray localPublicKeyArr,
        jbyteArray localTempCipherPriKeyArr, jobjectArray localTempPublicKeyArr,
        jbyteArray peerIdArr, jobjectArray peerPublicKeyArr, jobjectArray peerTempPublicKeyArr,
        jint secretLen, jboolean useClientMode) {
    unsigned int flag;
    char *ownPubKey = NULL;
    unsigned int ownPubKeyLen = 0;
    void *ownPriKeyHandle = NULL;
    char *ownTmpPubKey = NULL;
    unsigned int ownTmpPubKeyLen = 0;
    void *ownTmpPriKeyHandle = NULL;
    unsigned int keyBits;
    unsigned char *sponsorId = NULL;
    unsigned int sponsorIdLen;
    unsigned char *responseId = NULL;
    unsigned int responseIdLen;
    char *responsePubKey = NULL;
    unsigned int responsePubKeyLen = 0;
    char *responseTmpPubKey = NULL;
    unsigned int responseTmpPubKeyLen = 0;
    char *cipherKey = NULL;
    unsigned int cipherKeyLen = 0;

    SGD_RV rv;
    jbyteArray result = NULL;

    flag = useClientMode ? 1 : 0;
    ownPubKey = SDF_CreateSM2PublicKey(env, localPublicKeyArr, &ownPubKeyLen);
    ownPriKeyHandle = SDF_CreateSM2PriKeyHandle(env, localCipherPriKeyArr, NULL);

    ownTmpPubKey = SDF_CreateSM2PublicKey(env, localTempPublicKeyArr, &ownTmpPubKeyLen);
    ownTmpPriKeyHandle = SDF_CreateSM2PriKeyHandle(env, localTempCipherPriKeyArr, NULL);

    keyBits = secretLen;

    sponsorId = SDF_NewIDChars(env, localIdArr);
    sponsorIdLen = SDF_GetIDLen(env, localIdArr);

    responseId = SDF_NewIDChars(env, peerIdArr);
    responseIdLen = SDF_GetIDLen(env, peerIdArr);

    responsePubKey = SDF_CreateSM2PublicKey(env, peerPublicKeyArr, &responsePubKeyLen);
    responseTmpPubKey = SDF_CreateSM2PublicKey(env, peerTempPublicKeyArr, &responseTmpPubKeyLen);

    // compute cipherKeyLen
    if ((rv = CDM_PreMasterKeyExchangeSM2STD(flag, ownPubKey, ownPubKeyLen, ownPriKeyHandle,
            ownTmpPubKey, ownTmpPubKeyLen, ownTmpPriKeyHandle, keyBits, sponsorId, sponsorIdLen,
            responseId, responseIdLen, responsePubKey, responsePubKeyLen, responseTmpPubKey, responseTmpPubKeyLen,
            cipherKey, &cipherKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_PreMasterKeyExchangeSM2STD");
        goto cleanup;
    }

    if (!(cipherKey = malloc(cipherKeyLen))) {
        throwOutOfMemoryError(env, "malloc cipherKey failed");
        goto cleanup;
    }
    memset(cipherKey, 0, cipherKeyLen);

    if ((rv = CDM_PreMasterKeyExchangeSM2STD(flag, ownPubKey, ownPubKeyLen, ownPriKeyHandle,
            ownTmpPubKey, ownTmpPubKeyLen, ownTmpPriKeyHandle, keyBits, sponsorId, sponsorIdLen,
            responseId, responseIdLen, responsePubKey, responsePubKeyLen, responseTmpPubKey, responseTmpPubKeyLen,
            cipherKey, &cipherKeyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_PreMasterKeyExchangeSM2STD");
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, (jint) cipherKeyLen);
    (*env)->SetByteArrayRegion(env, result, 0, (jint) cipherKeyLen, (jbyte *) cipherKey);
cleanup:
    SDF_FreeSM2PublicKey(ownPubKey);
    SDF_FreeSM2PriKeyHandle(ownPriKeyHandle);

    SDF_FreeSM2PublicKey(ownTmpPubKey);
    SDF_FreeSM2PriKeyHandle(ownTmpPriKeyHandle);

    SDF_ReleaseIDChars(env, localIdArr, sponsorId);
    SDF_ReleaseIDChars(env, peerIdArr, responseId);

    SDF_FreeSM2PublicKey(responsePubKey);
    SDF_FreeSM2PublicKey(responseTmpPubKey);

    if (cipherKey) {
        free(cipherKey);
    }
    return result;
}
