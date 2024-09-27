#include "org_openeuler_sdf_wrapper_SDFPRFNative.h"
#include "sdf.h"
#include "sdf_util.h"


unsigned int GetPrfParameterFieldSize(JNIEnv *env, jobject prfParameterObj, char *field) {
    jclass prfParameterClass = (*env)->GetObjectClass(env, prfParameterObj);
    jfieldID fieldId = (*env)->GetFieldID(env, prfParameterClass, field, "I");
    jint fieldValue = (jint) (*env)->GetIntField(env, prfParameterObj, fieldId);

    if (prfParameterClass != NULL) {
        (*env)->DeleteLocalRef(env, prfParameterClass);
    }
    return fieldValue;
}

unsigned int GetKeySize(JNIEnv *env , jobject prfParameterObj) {
    unsigned int keySize = SYSCKEY_LEN;
    if (prfParameterObj != NULL) {
        // keyBlock size
        keySize = SYSCKEY_LEN * 4;
        unsigned int ivLen = GetPrfParameterFieldSize(env, prfParameterObj, "ivLength");
        keySize += ivLen * 2;
    }
    return keySize;
}

KEYLEN GetKEYLENFromObj(JNIEnv *env, jobject prfParameterObj) {
//    KEYLEN prfKLen;
    unsigned int cipherKeyLen = GetPrfParameterFieldSize(env, prfParameterObj, "cipherKeyLength");
    unsigned int ivLength = GetPrfParameterFieldSize(env, prfParameterObj, "ivLength");
    unsigned int macKeyLen = GetPrfParameterFieldSize(env, prfParameterObj, "macKeyLength");
    KEYLEN prfKLen = {macKeyLen,
                      macKeyLen,
                      cipherKeyLen,
                      cipherKeyLen,
                      ivLength,
                      ivLength};
    return prfKLen;
}


/*
 * Class:     org_openeuler_sdf_wrapper_SDFPRFNative
 * Method:    nativeGMTLSPRF
 * Signature: (J[B[B[B[BLorg/openeuler/sdf/wrapper/entity/SDFKeyPrfParameter;[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFPRFNative_nativeGMTLSPRF(JNIEnv *env, jclass cls,
        jlong sessionHandleAddr, jbyteArray secretArr, jstring labelStr, jbyteArray clientRandomArr,
        jbyteArray serverRandomArr, jobject prfParameterObj, jbyteArray sessionHashArr, jbyteArray handshakeHashArr) {
    SGD_HANDLE hSessionHandle = (SGD_HANDLE) sessionHandleAddr;
    unsigned char *secret = NULL;
    const char *label = NULL;
    unsigned char *clientRandom = NULL;
    unsigned char *serverRandom = NULL;
    unsigned char *sessionHash = NULL;
    unsigned char *handshakeHash = NULL;
    unsigned int labelLen = 0;
    unsigned int clientRandomLen = 0;
    unsigned int serverRandomLen = 0;
    unsigned int sessionHashLen = 0;
    unsigned int handshakeHashLen = 0;
    jbyteArray keyArr = NULL;
    KeyMaterials uiKeyMaterials = {0};
    unsigned char *pucKey = NULL;
    unsigned int pucKeyLen;
    SGD_RV rv;

    // get secret
    if (secretArr == NULL) {
        throwNullPointerException(env, "NativeGMTLSPRF failed. secretArr is Null.");
        goto cleanup;
    }
    secret = (*env)->GetByteArrayElements(env, secretArr, NULL);
    // get label
    if (labelStr == NULL) {
        throwNullPointerException(env, "NativeGMTLSPRF failed. labelArr is Null.");
        goto cleanup;
    }
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
    // get sessionHash. The sessionHash can be null, but not when 'extended master secret'.
    if (sessionHashArr != NULL) {
        sessionHash = (*env)->GetByteArrayElements(env, sessionHashArr, NULL);
        sessionHashLen = (*env)->GetArrayLength(env, sessionHashArr);
    }
    // get handshakeHash. The handshakeHash can be null, but not when 'client finished' or 'server finished'.
    if (handshakeHashArr != NULL) {
        handshakeHash = (*env)->GetByteArrayElements(env, handshakeHashArr, NULL);
        handshakeHashLen = (*env)->GetArrayLength(env, handshakeHashArr);
    }

    // put uiKeyMaterials
    uiKeyMaterials.uiCHashKey = secret;
    uiKeyMaterials.uiLabel = label;
    uiKeyMaterials.uiLabelLength = labelLen;

    if (strcmp(label, LABAL_EMS) == 0) {
        // extended master secret
        uiKeyMaterials.uiSessionHash = sessionHash;
        uiKeyMaterials.uiSHLen = sessionHashLen;
        pucKeyLen = SYSCKEY_LEN;
    } else if ((strcmp(label, LABAL_CF) == 0) || (strcmp(label, LABAL_SF) == 0)) {
        // client finished or server finished
        uiKeyMaterials.uiHandshakeHash = handshakeHash;
        uiKeyMaterials.uiHHLen = handshakeHashLen;
        pucKeyLen = 12;
    } else {
        // master secret or pucKey expansion
        uiKeyMaterials.uiServerRandom = serverRandom;
        uiKeyMaterials.uiSRLen = serverRandomLen;
        uiKeyMaterials.uiClientRandom = clientRandom;
        uiKeyMaterials.uiCRLen = clientRandomLen;
        pucKeyLen = GetKeySize(env, prfParameterObj);
    }

    if ((pucKey = malloc(pucKeyLen)) == NULL) {
        throwOutOfMemoryError(env, "NativeGMTLSPRF failed. Unable to allocate in 'pucKey' buffer");
        goto cleanup;
    }
    memset(pucKey, 0, pucKeyLen);

    unsigned int size = 0;
    if (prfParameterObj != NULL) {
        // deriving work Key
        KEYLEN uiWorkKeyLen = GetKEYLENFromObj(env, prfParameterObj);
        rv = SDF_HW_PRF(hSessionHandle, SGD_SM3, &uiKeyMaterials, &uiWorkKeyLen, pucKey, &size);
    } else {
        // deriving master secret
        rv = SDF_HW_PRF(hSessionHandle, SGD_SM3, &uiKeyMaterials, 0, pucKey, &size);
    }
    if (rv) {
        throwSDFException(env, rv);
        goto cleanup;
    }
    // new keyArr
    keyArr = (*env)->NewByteArray(env, size);
    (*env)->SetByteArrayRegion(env, keyArr, 0, size, (jbyte *) pucKey);
cleanup:
    if (secret != NULL) {
        (*env)->ReleaseByteArrayElements(env, secretArr, secret, 0);
    }
    if (label != NULL) {
        (*env)->ReleaseStringUTFChars(env, labelStr, label);
    }
    if (clientRandom != NULL) {
        (*env)->ReleaseByteArrayElements(env, clientRandomArr, clientRandom, 0);
    }
    if (serverRandom != NULL) {
        (*env)->ReleaseByteArrayElements(env, serverRandomArr, serverRandom, 0);
    }
    if (sessionHash != NULL) {
        (*env)->ReleaseByteArrayElements(env, sessionHashArr, sessionHash, 0);
    }
    if (handshakeHash != NULL) {
        (*env)->ReleaseByteArrayElements(env, handshakeHashArr, handshakeHash, 0);
    }
    if (pucKey != NULL) {
        free(pucKey);
    }
    return keyArr;
}