#include "cryptocard/crypto_sdk_vf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFRSACipherNative.h"
#include "sdf_util.h"

static jbyte *SDF_GetRSAKeyParams(JNIEnv *env, jobjectArray params, SDF_RSAKeyParamIndex index, int len) {
    jbyte *bytes = NULL;
    jbyteArray array = NULL;
    array = (jbyteArray) (*env)->GetObjectArrayElement(env, params, index);
    int arrayLen = (*env)->GetArrayLength(env, array);
    if (arrayLen > len) {
        throwSDFRuntimeException(env, "arrayLen is more than given len");
        goto cleanup;
    }
    if (!(bytes = malloc(len))) {
        throwOutOfMemoryError(env, "malloc failed");
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, array, 0, arrayLen, bytes + (len - arrayLen));
cleanup:
    return bytes;
}

static void SDF_ReleaseRSAKeyParams(jbyte *bytes) {
    if (bytes) {
        free(bytes);
    }
}

unsigned char *SDF_NewRSAPublicKeyChars(JNIEnv *env, jint bits, jobjectArray pubKeyParams,
        unsigned int uiKeyType, unsigned int *uiPBKLen) {
    unsigned char *uiPublicKey = NULL;

    jbyte *m = NULL;
    jbyte *e = NULL;

    if (!(m = SDF_GetRSAKeyParams(env, pubKeyParams, SDF_RSA_PBK_M_IDX, ExRSAref_MAX_LEN))) {
        goto cleanup;
    }
    if (!(e = SDF_GetRSAKeyParams(env, pubKeyParams, SDF_RSA_PBK_E_IDX, ExRSAref_MAX_LEN))) {
        goto cleanup;
    }

    unsigned int PBKLen = SDF_GetAsymmetricPBKLen(uiKeyType);
    RSArefPublicKeyEx *rsaPublicKeyEx = malloc(PBKLen);
    if (!rsaPublicKeyEx) {
        throwOutOfMemoryError(env, "malloc RSArefPublicKeyEx failed");
        goto cleanup;
    }
    memset(rsaPublicKeyEx, 0, PBKLen);
    rsaPublicKeyEx->bits = bits;
    memcpy(rsaPublicKeyEx->m, m, ExRSAref_MAX_LEN);
    memcpy(rsaPublicKeyEx->e, e, ExRSAref_MAX_LEN);

    uiPublicKey = (unsigned char *) rsaPublicKeyEx;
    *uiPBKLen = PBKLen;

cleanup:
    SDF_ReleaseRSAKeyParams(m);
    SDF_ReleaseRSAKeyParams(e);
    return uiPublicKey;
}

void SDF_ReleaseRSAPublicKeyChars(unsigned char *uiPublicKey) {
    if (uiPublicKey == NULL) {
        return;
    }
    free(uiPublicKey);
}


unsigned char *SDF_NewRSAPrivateKeyChars(JNIEnv *env, int bits, jobjectArray priKeyParams,
        unsigned int uiKeyType, unsigned int *uiPRKLen) {
    unsigned char *uiPriKey = NULL;

    jbyte *m = NULL;
    jbyte *e = NULL;
    jbyte *d = NULL;
    jbyte *p = NULL;
    jbyte *q = NULL;
    jbyte *pe = NULL;
    jbyte *qe = NULL;
    jbyte *coeff = NULL;

    if (!(m = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PBK_M_IDX, ExRSAref_MAX_LEN))) {
        goto cleanup;
    }
    if (!(e = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PBK_E_IDX, ExRSAref_MAX_LEN))) {
        goto cleanup;
    }
    if (!(d = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PRK_D_IDX, ExRSAref_MAX_LEN))) {
        goto cleanup;
    }
    if (!(p = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PRK_PRIME_P_IDX, ExRSAref_MAX_PLEN))) {
        goto cleanup;
    }
    if (!(q = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PRK_PRIME_Q_IDX, ExRSAref_MAX_PLEN))) {
        goto cleanup;
    }
    if (!(pe = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PRK_PRIME_EXPONENT_P_IDX, ExRSAref_MAX_PLEN))) {
        goto cleanup;
    }
    if (!(qe = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PRK_PRIME_EXPONENT_Q_IDX, ExRSAref_MAX_PLEN))) {
        goto cleanup;
    }
    if (!(coeff = SDF_GetRSAKeyParams(env, priKeyParams, SDF_RSA_PRK_PRIME_COEFF_IDX, ExRSAref_MAX_PLEN))) {
        goto cleanup;
    }

    unsigned int PRKLen = SDF_GetAsymmetricPRKLen(uiKeyType);
    RSArefPrivateKeyEx *privateKey = malloc(PRKLen);
    if (!privateKey) {
        throwOutOfMemoryError(env, "malloc RSArefPublicKeyEx failed");
        goto cleanup;
    }
    memset(privateKey, 0, PRKLen);
    privateKey->bits = bits;
    memcpy(privateKey->m, m, ExRSAref_MAX_LEN);
    memcpy(privateKey->e, e, ExRSAref_MAX_LEN);
    memcpy(privateKey->d, d, ExRSAref_MAX_LEN);
    memcpy(privateKey->prime[0], p, ExRSAref_MAX_PLEN);
    memcpy(privateKey->prime[1], q, ExRSAref_MAX_PLEN);
    memcpy(privateKey->pexp[0], pe, ExRSAref_MAX_PLEN);
    memcpy(privateKey->pexp[1], qe, ExRSAref_MAX_PLEN);
    memcpy(privateKey->coef, coeff, ExRSAref_MAX_PLEN);

    uiPriKey = (unsigned char *) privateKey;
    *uiPRKLen = PRKLen;

cleanup:
    SDF_ReleaseRSAKeyParams(m);
    SDF_ReleaseRSAKeyParams(e);
    SDF_ReleaseRSAKeyParams(d);
    SDF_ReleaseRSAKeyParams(p);
    SDF_ReleaseRSAKeyParams(q);
    SDF_ReleaseRSAKeyParams(pe);
    SDF_ReleaseRSAKeyParams(qe);
    SDF_ReleaseRSAKeyParams(coeff);
    return uiPriKey;
}


void SDF_ReleaseRSAPrivateKeyChars(unsigned char *uiPriKey) {
    if (uiPriKey == NULL) {
        return;
    }
    free(uiPriKey);
}

/*
 * Class:     org_openeuler_sdf_wrapper_SDFRSACipherNative
 * Method:    nativeEncrypt
 * Signature: (JI[[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFRSACipherNative_nativeEncrypt
        (JNIEnv *env, jclass cls, jint bits, jobjectArray pubKeyParams, jbyteArray data) {
    unsigned int uiKeyType = DATA_KEY_RSA;
    unsigned char *uiPublicKey = NULL;
    unsigned int uiPBKLen = 0;
    unsigned char *pucData = NULL;
    unsigned int uiDataLength;
    unsigned char *pucEncData = NULL;
    unsigned int pEDLen = 0;

    SGD_RV rv;
    jbyteArray result = NULL;

    uiPublicKey = SDF_NewRSAPublicKeyChars(env, bits, pubKeyParams, uiKeyType, &uiPBKLen);
    if (!uiPublicKey) {
        goto cleanup;
    }
    pucData = (unsigned char *) (*env)->GetByteArrayElements(env, data, 0);
    uiDataLength = (*env)->GetArrayLength(env, data);

    pEDLen = (bits + 7) >> 3;
    if (!(pucEncData = malloc(pEDLen))) {
        throwOutOfMemoryError(env, "malloc pucEncData failed");
        goto cleanup;
    }

    if ((rv = CDM_AsymEncrypt(uiKeyType, uiPublicKey, uiPBKLen,
            pucData, uiDataLength, pucEncData, &pEDLen)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, pEDLen);
    (*env)->SetByteArrayRegion(env, result, 0, pEDLen, pucEncData);

cleanup:
    SDF_ReleaseRSAPublicKeyChars(uiPublicKey);
    if (pucData) {
        (*env)->ReleaseByteArrayElements(env, data, pucData, 0);
    }
    if (pucEncData) {
        free(pucEncData);
    }
    return result;
}


/*
 * Class:     org_openeuler_sdf_wrapper_SDFRSACipherNative
 * Method:    nativeDecrypt
 * Signature: (JI[[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFRSACipherNative_nativeDecrypt
        (JNIEnv *env, jclass cls, jint bits, jobjectArray privateKeyParams, jbyteArray encData) {
    unsigned int uiKeyType = DATA_KEY_RSA;
    unsigned char *uiPriKey = NULL;
    unsigned int uiPIKLen = 0;
    unsigned char *pucEncData = NULL;
    unsigned int pEDLen = 0;
    unsigned char *pucData = NULL;
    unsigned int puiDataLength = 0;
    jbyteArray result = NULL;

    SGD_RV rv;

    uiPriKey = SDF_NewRSAPrivateKeyChars(env, bits, privateKeyParams, uiKeyType, &uiPIKLen);
    if (!uiPriKey) {
        goto cleanup;
    }

    pucEncData = (unsigned char *) (*env)->GetByteArrayElements(env, encData, 0);
    pEDLen = (*env)->GetArrayLength(env, encData);

    if (!(pucData = malloc(pEDLen))) {
        throwOutOfMemoryError(env, "malloc pucEncData failed");
        goto cleanup;
    }

    if ((rv = CDM_AsymDecrypt(uiKeyType, uiPriKey, uiPIKLen, pucEncData, pEDLen, pucData,
            &puiDataLength) != SDR_OK)) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, puiDataLength);
    (*env)->SetByteArrayRegion(env, result, 0, puiDataLength, pucData);
cleanup:
    SDF_ReleaseRSAPrivateKeyChars(uiPriKey);
    if (pucEncData) {
        (*env)->ReleaseByteArrayElements(env, encData, pucEncData, 0);
    }
    if (pucData) {
        free(pucData);
    }
    return result;


}