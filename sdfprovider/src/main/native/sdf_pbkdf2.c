#include "org_openeuler_sdf_wrapper_SDFPBKDF2Native.h"
#include "sdf.h"
#include "sdf_exception.h"
#include "sdf_util.h"
/*
 * Class:     org_openeuler_sdf_wrapper_SDFPBKDF2Native
 * Method:    nativeDeriveKey
 * Signature: (JLjava/lang/String;[B[BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFPBKDF2Native_nativeDeriveKey
  (JNIEnv *env, jclass clazz, jlong sessionAddress, jstring digestAlgo, jbyteArray password,
          jbyteArray salt, jint iterCount, jint keyLength) {
    const char *algoUtf = NULL;
    void *hSessionHandle = (void *) sessionAddress;
    unsigned int uiAlgID;
    unsigned char *uiPass = NULL;
    unsigned int uiPasslen;
    unsigned char *uiSalt = NULL;
    unsigned int uiSaltlen;
    unsigned int uiCount = iterCount;
    unsigned int keylen = keyLength;
    unsigned char pResult[keylen];
    jbyteArray result = NULL;

    algoUtf = (*env)->GetStringUTFChars(env, digestAlgo, NULL);
    uiAlgID = SDF_GetDigestAlgoId(algoUtf);
    if (uiAlgID == SDF_INVALID_VALUE) {
        throwIllegalArgumentException(env,"UnSupport digest algorithm");
        goto cleanup;
    }
    uiPass = (*env)->GetByteArrayElements(env, password, NULL);
    uiPasslen = (*env)->GetArrayLength(env, password);
    uiSalt = (*env)->GetByteArrayElements(env, salt, NULL);
    uiSaltlen = (*env)->GetArrayLength(env, salt);
    
    SGD_RV rv;
    if ((rv = SDF_HW_PBKDF2(hSessionHandle, uiAlgID, uiPass, uiPasslen, uiSalt, uiSaltlen,
            uiCount, keylen, pResult)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, keylen);
    (*env)->SetByteArrayRegion(env, result, 0, keylen, pResult);

cleanup:
    if (algoUtf) {
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoUtf);
    }
    if (uiPass) {
        (*env)->ReleaseByteArrayElements(env, password, uiPass, 0);
    }
    if (uiSalt) {
        (*env)->ReleaseByteArrayElements(env, salt, uiSalt, 0);
    }
    return result;
}