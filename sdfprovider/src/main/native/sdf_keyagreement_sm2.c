#include "org_openeuler_sdf_wrapper_SDFSM2KeyAgreementNative.h"
#include "sdf.h"
#include "sdf_util.h"

unsigned char *SDF_NewSM2PublicKeyChars(JNIEnv *env, jobject publicKeyObj) {
    ECCrefPublicKey_HW *publicKey = SDF_GetECCPublickeyFromObj(env, publicKeyObj);
    if (!publicKey) {
        return NULL;
    }
    return (unsigned char *) publicKey;
}

void SDF_ReleaseSM2PublicKeyChars(unsigned char *publicKey) {
    if (publicKey) {
        free(publicKey);
    }
}

unsigned char *SDF_NewSM2PrivateKeyChars(JNIEnv *env, jbyteArray privateKeyArr) {
    return (unsigned char *) (*env)->GetByteArrayElements(env, privateKeyArr, 0);
}

void SDF_ReleaseSM2PrivateKeyChars(JNIEnv *env, jbyteArray privateKeyArr, unsigned char *privateKeyBytes) {
    if (privateKeyBytes) {
        (*env)->ReleaseByteArrayElements(env, privateKeyArr, (jbyte *) privateKeyBytes, 0);
    }
}

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
        JNIEnv *env, jclass cls, jlong sessionHandleAddr,
        jbyteArray localIdArr, jbyteArray localCipherPriKeyArr, jobject localPublicKeyObj,
        jbyteArray tempCipherPriKeyArr, jobject tempPublicKeyObj,
        jbyteArray peerIdArr, jobject peerPublicKeyObj, jobject peerTempPublicKeyObj,
        jint secretLen, jboolean useClientMode) {
    SGD_HANDLE *hSessionHandle = (SGD_HANDLE *) sessionHandleAddr;
    unsigned int Flag;
    unsigned char *OwnPublicKey = NULL;
    unsigned int OPBKLen;
    unsigned char *OwnPrivateKey = NULL;
    unsigned int OCPIKLen;
    unsigned char *OwnTmpPublicKey = NULL;
    unsigned int OTPBKLen;
    unsigned char *OwnTmpPrivateKey = NULL;
    unsigned int OTPIKLen;
    unsigned int uiKeyBits;
    unsigned char *pucSponsorID = NULL;
    unsigned int uiSponsorIDLength;
    unsigned char *pucResponseID = NULL;
    unsigned int uiResponseIDLength;
    unsigned char *pucResponsePublicKey = NULL;
    unsigned int RPBKLen;
    unsigned char *pucResponseTmpPublicKey = NULL;
    unsigned int RTPBKLen;
    unsigned char *pCipherKey = NULL;
    unsigned int pCKLen;

    unsigned int uiType = SDF_ASYMMETRIC_KEY_TYPE_SM2;
    unsigned int PBKLen = SDF_GetAsymmetricPBKLen(uiType);
    unsigned int PRKLen = SDF_GetAsymmetricPRKLen(uiType);
    SGD_RV rv;
    jbyteArray result = NULL;

    Flag = useClientMode ? 1 : 0;
    OwnPublicKey = SDF_NewSM2PublicKeyChars(env, localPublicKeyObj);
    OPBKLen = PBKLen;

    OwnPrivateKey = SDF_NewSM2PrivateKeyChars(env, localCipherPriKeyArr);
    OCPIKLen = PRKLen;

    OwnTmpPublicKey = SDF_NewSM2PublicKeyChars(env, tempPublicKeyObj);
    OTPBKLen = PBKLen;

    OwnTmpPrivateKey = SDF_NewSM2PrivateKeyChars(env, tempCipherPriKeyArr);
    OTPIKLen = PRKLen;

    uiKeyBits = secretLen;

    pucSponsorID = SDF_NewIDChars(env, localIdArr);
    uiSponsorIDLength = SDF_GetIDLen(env, localIdArr);

    pucResponseID = SDF_NewIDChars(env, peerIdArr);
    uiResponseIDLength = SDF_GetIDLen(env, peerIdArr);

    pucResponsePublicKey = SDF_NewSM2PublicKeyChars(env, peerPublicKeyObj);
    RPBKLen = PBKLen;

    pucResponseTmpPublicKey = SDF_NewSM2PublicKeyChars(env, peerTempPublicKeyObj);
    RTPBKLen = PBKLen;

    if (!(pCipherKey = malloc(SYSCKEY_LEN))) {
        throwOutOfMemoryError(env, "malloc pCipherKey failed");
        goto cleanup;
    }
    memset(pCipherKey, 0, SYSCKEY_LEN);

    if ((rv = SDF_HW_PreMasterKeyExchange_SM2STD(hSessionHandle, Flag, OwnPublicKey, OPBKLen, OwnPrivateKey, OCPIKLen,
            OwnTmpPublicKey, OTPBKLen, OwnTmpPrivateKey, OTPIKLen, uiKeyBits, pucSponsorID, uiSponsorIDLength,
            pucResponseID, uiResponseIDLength, pucResponsePublicKey, RPBKLen, pucResponseTmpPublicKey, RTPBKLen,
            pCipherKey, &pCKLen)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, (jint) pCKLen);
    (*env)->SetByteArrayRegion(env, result, 0, (jint) pCKLen, (jbyte *) pCipherKey);
cleanup:
    SDF_ReleaseSM2PublicKeyChars(OwnPublicKey);
    SDF_ReleaseSM2PrivateKeyChars(env, localCipherPriKeyArr, OwnPrivateKey);

    SDF_ReleaseSM2PublicKeyChars(OwnTmpPublicKey);
    SDF_ReleaseSM2PrivateKeyChars(env, tempCipherPriKeyArr, OwnTmpPrivateKey);

    SDF_ReleaseIDChars(env, localIdArr, pucSponsorID);
    SDF_ReleaseIDChars(env, peerIdArr, pucResponseID);

    SDF_ReleaseSM2PublicKeyChars(pucResponsePublicKey);
    SDF_ReleaseSM2PublicKeyChars(pucResponseTmpPublicKey);

    if (pCipherKey) {
        free(pCipherKey);
    }
    return result;
}
