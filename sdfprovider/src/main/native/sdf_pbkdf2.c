#include "cryptocard/crypto_sdk_vf.h"
#include "cryptocard/errno.h"

#include "org_openeuler_sdf_wrapper_SDFPBKDF2Native.h"
#include "sdf_exception.h"
#include "sdf_util.h"

JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFPBKDF2Native_nativeDeriveKey
  (JNIEnv *env, jclass clazz, jstring digestAlgo, jbyteArray passwordArr,
          jbyteArray saltArr, jint iterCount, jint keyLength) {
    const char *algoUtf = NULL;
    unsigned int algId;
    unsigned char *pass = NULL;
    unsigned int passLen;
    unsigned char *salt = NULL;
    unsigned int saltLen;
    unsigned int count = iterCount;
    unsigned int keyLen = keyLength;
    unsigned char pResult[keyLen];
    jbyteArray result = NULL;

    algoUtf = (*env)->GetStringUTFChars(env, digestAlgo, NULL);
    algId = SDF_GetDigestAlgoId(algoUtf);
    if (algId == SDF_INVALID_VALUE) {
        throwIllegalArgumentException(env,"UnSupport digest algorithm");
        goto cleanup;
    }
    pass = (*env)->GetByteArrayElements(env, passwordArr, NULL);
    passLen = (*env)->GetArrayLength(env, passwordArr);
    salt = (*env)->GetByteArrayElements(env, saltArr, NULL);
    saltLen = (*env)->GetArrayLength(env, saltArr);
    
    SGD_RV rv;
    if ((rv = CDM_PBKDF2(algId, pass, passLen, salt, saltLen,
            count, keyLen, pResult)) != SDR_OK) {
        throwSDFException(env, rv, "CDM_PBKDF2");
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, keyLen);
    (*env)->SetByteArrayRegion(env, result, 0, keyLen, pResult);

cleanup:
    if (algoUtf) {
        (*env)->ReleaseStringUTFChars(env, digestAlgo, algoUtf);
    }
    if (pass) {
        (*env)->ReleaseByteArrayElements(env, passwordArr, pass, 0);
    }
    if (salt) {
        (*env)->ReleaseByteArrayElements(env, saltArr, salt, 0);
    }
    return result;
}