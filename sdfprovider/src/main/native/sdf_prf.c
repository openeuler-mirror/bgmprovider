#include "cryptocard/crypto_sdk_vf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFPRFNative.h"
#include "sdf_util.h"

// create WorkKeyLen
WorkKeyLen *SDF_CreateWorkKeyLen(JNIEnv *env, const char *label, unsigned int macKeyLen, unsigned int cipherKeyLen,
        unsigned int ivLen, unsigned int macKeyType, unsigned int encKeyType) {
    WorkKeyLen *workKeyLen = NULL;
    if (strcmp(label, LABAL_KE) != 0) {
        return workKeyLen;
    }
    if (!(workKeyLen = malloc(sizeof(WorkKeyLen)))) {
        throwOutOfMemoryError(env, "malloc workKeyLen failed");
        return workKeyLen;
    }
    workKeyLen->macKeyLenClient = macKeyLen;
    workKeyLen->macKeyLenServer = macKeyLen;
    workKeyLen->encKeyLenClient = cipherKeyLen;
    workKeyLen->encKeyLenServer = cipherKeyLen;
    workKeyLen->macKeyTypeClient = macKeyType;
    workKeyLen->macKeyTypeServer = macKeyType;
    workKeyLen->encKeyTypeClient = encKeyType;
    workKeyLen->encKeyTypeServer = encKeyType;
    workKeyLen->ivClient = ivLen;
    workKeyLen->ivServer = ivLen;
    return workKeyLen;
}

// free WorkKeyLen
void SDF_FreeWorkKeyLen(WorkKeyLen *workKeyLen) {
    if (workKeyLen == NULL) {
        return;
    }
    free(workKeyLen);
}

// create KeyMaterials
KeyMaterials *SDF_CreateKeyMaterials(JNIEnv *env, void *keyHandle, const char *label, unsigned int labelLength,
        unsigned char *serverRandom, unsigned int serverRandomLen,
        unsigned char *clientRandom, unsigned int clientRandomLen,
        unsigned char *sslHash, unsigned int sslHashLen) {
    KeyMaterials *keyMaterials = NULL;
    if (!(keyMaterials = calloc(sizeof(KeyMaterials), 1))) {
        throwOutOfMemoryError(env, "malloc workKeyLen failed");
        return keyMaterials;
    }
    keyMaterials->keyHandle = keyHandle;
    //keyMaterials->label = label;
    strncpy(keyMaterials->label, label, labelLength);
    keyMaterials->labelLength = labelLength;

    if (strcmp(label, LABAL_EMS) == 0 || strcmp(label, LABAL_CF) == 0 || strcmp(label, LABAL_SF) == 0) {
        // extended master secret, client finished, server finished
        //keyMaterials->sslHash = sslHash;
        memcpy(keyMaterials->sslHash, sslHash, sslHashLen);
        keyMaterials->sslHashLen = sslHashLen;
    } else {
        // master secret or key expansion
        //keyMaterials->serverRandom = serverRandom;
        memcpy(keyMaterials->serverRandom, serverRandom, serverRandomLen);
        keyMaterials->serverRandomLen = serverRandomLen;
        // keyMaterials->clientRandom = clientRandom;
        memcpy(keyMaterials->clientRandom, clientRandom, clientRandomLen);
        keyMaterials->clientRandomLen = clientRandomLen;
    }
    return keyMaterials;
}

// free KeyMaterials
void SDF_FreeKeyMaterials(KeyMaterials *keyMaterials) {
    if (keyMaterials == NULL) {
        return;
    }
    free(keyMaterials);
}

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFPRFNative_nativeGMTLSPRF(JNIEnv *env, jclass cls,
        jstring prfHashAlgStr, jstring encKeyAlgStr, jbyteArray secretArr, jstring labelStr, jbyteArray clientRandomArr,
        jbyteArray serverRandomArr,
        jbyteArray sslHashArr, int macKeyLen, int cipherKeyLen, int ivLen) {
    unsigned int algId;
    const char *prfHashAlg = NULL;
    const char *encKeyAlg = NULL;
    unsigned int macKeyType;
    unsigned int encKeyType;
    unsigned char *secret = NULL;
    unsigned int secretLen = 0;
    void *keyHandle = NULL;
    const char *label = NULL;
    unsigned int labelLen = 0;
    unsigned char *clientRandom = NULL;
    unsigned int clientRandomLen = 0;
    unsigned char *serverRandom = NULL;
    unsigned int serverRandomLen = 0;
    unsigned char *sslHash = NULL;
    unsigned int sslHashLen = 0;
    jbyteArray keyArr = NULL;
    KeyMaterials *keyMaterials = NULL;
    WorkKeyLen *workKeyLen = NULL;
    unsigned char *key = NULL;
    unsigned int keyLen = 0;
    SGD_RV rv;

    if (prfHashAlgStr == NULL) {
        throwIllegalArgumentException(env, "prfHashAlgStr cannot be null");
        goto cleanup;
    }
    if (labelStr == NULL) {
        throwNullPointerException(env, "labelStr cannot be null");
        goto cleanup;
    }

    // get algId
    prfHashAlg = (*env)->GetStringUTFChars(env, prfHashAlgStr, NULL);
    algId = SDF_GetDigestAlgoId(prfHashAlg);

    macKeyType = SDF_GetHmacKeyType(prfHashAlg);

    // fprintf(stderr, "algId=%d\n", algId);
    // fprintf(stderr, "macKeyType=%d\n", macKeyType);

    if (encKeyAlgStr != NULL) {
        encKeyAlg = (*env)->GetStringUTFChars(env, encKeyAlgStr, NULL);
        encKeyType = SDF_GetSymmetricKeyType(encKeyAlg);
        // fprintf(stderr, "encKeyType=%d\n", encKeyType);
    }

    // get secret
    secret = (*env)->GetByteArrayElements(env, secretArr, NULL);
    secretLen = (*env)->GetArrayLength(env, secretArr);
    if ((rv = CDM_ImportKeyHandle(secret, secretLen, NULL, 0, &keyHandle)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_ImportKeyHandle");
        goto cleanup;
    }

    // get label
    label = (*env)->GetStringUTFChars(env, labelStr, NULL);
    labelLen = (*env)->GetStringLength(env, labelStr);

    // get clientRandom. The clientRandom can be null and is used when 'master secret'.
    if (clientRandomArr != NULL) {
        clientRandom = (*env)->GetByteArrayElements(env, clientRandomArr, NULL);
        clientRandomLen = (*env)->GetArrayLength(env, clientRandomArr);
    }

    // get serverRandom. The serverRandom can be null and is used when 'master secret'.
    if (serverRandomArr != NULL) {
        serverRandom = (*env)->GetByteArrayElements(env, serverRandomArr, NULL);
        serverRandomLen = (*env)->GetArrayLength(env, serverRandomArr);
    }

    // get sslHash. The sslHash can be null, but not when 'extended master secret'.
    if (sslHashArr != NULL) {
        sslHash = (*env)->GetByteArrayElements(env, sslHashArr, NULL);
        sslHashLen = (*env)->GetArrayLength(env, sslHashArr);
    }

    // keyMaterials
    if ((keyMaterials = SDF_CreateKeyMaterials(env, keyHandle, label, labelLen,
            serverRandom, serverRandomLen, clientRandom, clientRandomLen, sslHash, sslHashLen)) == NULL) {
        goto cleanup;
    }

    // workKeyLen
    workKeyLen = SDF_CreateWorkKeyLen(env, label, macKeyLen, cipherKeyLen, ivLen, macKeyType, encKeyType);
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    // compute key len
    if ((rv = CDM_PRF(algId, keyMaterials, workKeyLen, key, &keyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_PRF");
        goto cleanup;
    }
    // printf("keyLen=%d\n", keyLen);

    // key
    if ((key = malloc(keyLen)) == NULL) {
        throwOutOfMemoryError(env, "malloc");
        goto cleanup;
    }

    // compute prf
    if ((rv = CDM_PRF(algId, keyMaterials, workKeyLen, key, &keyLen)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_PRF");
        goto cleanup;
    }

    // new keyArr
    keyArr = (*env)->NewByteArray(env, keyLen);
    (*env)->SetByteArrayRegion(env, keyArr, 0, keyLen, (jbyte *) key);

cleanup:
    if (key != NULL) {
        free(key);
    }
    SDF_FreeWorkKeyLen(workKeyLen);
    SDF_FreeKeyMaterials(keyMaterials);
    if (sslHash != NULL) {
        (*env)->ReleaseByteArrayElements(env, sslHashArr, sslHash, 0);
    }
    if (serverRandom != NULL) {
        (*env)->ReleaseByteArrayElements(env, serverRandomArr, serverRandom, 0);
    }
    if (clientRandom != NULL) {
        (*env)->ReleaseByteArrayElements(env, clientRandomArr, clientRandom, 0);
    }
    if (label != NULL) {
        (*env)->ReleaseStringUTFChars(env, labelStr, label);
    }
    if (keyHandle != NULL) {
        CDM_DestroyKeyHandle(keyHandle);
    }
    if (secret != NULL) {
        (*env)->ReleaseByteArrayElements(env, secretArr, secret, 0);
    }
    if (encKeyAlg != NULL) {
        (*env)->ReleaseStringUTFChars(env, encKeyAlgStr, encKeyAlg);
    }
    if (prfHashAlg != NULL) {
        (*env)->ReleaseStringUTFChars(env, prfHashAlgStr, prfHashAlg);
    }

    return keyArr;
}