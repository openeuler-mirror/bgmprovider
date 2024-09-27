#include <string.h>
#include "sdf.h"
#include "sdf_util.h"


// SDF_HW_EncryptSecretkeyWithoutPlaintext uiKeyType
#define HW_SM2                      0
#define HW_RSA                      1
#define HW_ECC                      2
#define HW_SM9                      3
#define HW_SYM                      4
#define HW_HMAC                     5

/*
void print(char *p, int count) {
    int i = 0;
    while (i < count) {
        int c = p[i++];
        if (c >= 128) {
            c = c - 256;
        }
        printf("%d, ", c);
    }
    printf("\n");
}

void generate_enc_key(int uiKeyType, unsigned char *uiPalinKey, unsigned int uiPKLen) {
    SGD_HANDLE hDeviceHandle;
    SGD_HANDLE hSessionHandle;
    SGD_RV rv;
    rv = SDF_OpenDevice(&hDeviceHandle);
    printf("rv=%x\n", rv);
    if (rv) {
        printf("SDF_OpenDevice failed\n");
        return;
    }
    rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
    printf("rv=%x\n", rv);
    if (rv) {
        printf("SDF_OpenSession failed\n");
        return;
    }

    KEKInfo uiKEKInfo = {0};
    memcpy(uiKEKInfo.KEKID, "KekId123456789012345678901234567", 32);
    memcpy(uiKEKInfo.RegionID, "RegionID1", 9);
    memcpy(uiKEKInfo.CdpID, "CdpID1", 6);

    unsigned int uiAlgID = SGD_SM4_ECB;
    unsigned char *IV = NULL;
    unsigned int IVLen = 0;
    unsigned char *uiPIN = NULL;
    unsigned int uiPINLen = 0;


    unsigned char pCipherKey[10240] = {0};
    unsigned int pCKLen;


    rv = SDF_HW_EncryptSecretkeyWithoutPlaintext(
            hSessionHandle,
            uiAlgID,
            IV,
            IVLen,
            uiPIN,
            uiPINLen,
            &uiKEKInfo,
            uiKeyType,
            uiPalinKey,
            uiPKLen,
            pCipherKey,
            &pCKLen);


    printf("rv=%x\n", rv);
    printf("pCKLen=%d\n", pCKLen);
    print(pCipherKey, pCKLen);

    SysCKey *sysCKey = (SysCKey *) pCipherKey;

    signed char t = 128;

    printf("t = %d\n", t);
}

void main() {
    int uiKeyType = HW_SYM;
    unsigned char uiPalinKey[] = {
            -78, 13, -71, 96, 114, 81, 24, -77, -88, -29, -102, -80, 100, 78, 115, -107
    };
    unsigned int uiPKLen = sizeof(uiPalinKey);
    generate_enc_key(uiKeyType, uiPalinKey, uiPKLen);
}*/


/*
 * Class:     org_openeuler_sdf_wrapper_SDFInternalNative
 * Method:    encryptKey
 * Signature: (J[B[B[B[BI[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_openeuler_sdf_wrapper_SDFInternalNative_encryptKey
        (JNIEnv *env, jclass clazz, jlong sessionAddr, jbyteArray kekId, jbyteArray regionId, jbyteArray cdpId,
                jbyteArray pin, jint uiType, jbyteArray plainKey) {

    void *hSessionHandle = (void *) sessionAddr;
    unsigned int uiAlgID = SGD_SM4_ECB;
    unsigned char *IV = NULL;
    unsigned int IVLen = 0;
    unsigned char *uiPIN = NULL;
    unsigned int uiPINLen = 0;
    unsigned int uiKeyType = uiType;
    unsigned char *uiPlainKey = NULL;
    unsigned int uiPKLen = 0;
    unsigned int pCKLen = 0;
    unsigned char pCipherKey[10240];
    KEKInfo *uiKEKInfo = NULL;
    jbyteArray encKeyArr = NULL;

    uiKEKInfo = SDF_NewKEKInfo(env, kekId, regionId, cdpId);
    if (!uiKEKInfo) {
        throwSDFRuntimeException(env, "SDF_NewKEKInfo failed");
        goto cleanup;
    }

    if (!plainKey) {
        throwIllegalArgumentException(env, "plainKey should not be null ");
        goto cleanup;
    }
    uiPlainKey = (*env)->GetByteArrayElements(env, plainKey, NULL);
    uiPKLen = (*env)->GetArrayLength(env, plainKey);

    if (pin) {
        uiPIN = (*env)->GetByteArrayElements(env, pin, NULL);
        uiPINLen = (*env)->GetArrayLength(env, pin);
    }

    SGD_RV rv;

    if ((rv = SDF_HW_EncryptSecretkeyWithoutPlaintext(
            hSessionHandle,
            uiAlgID,
            IV,
            IVLen,
            uiPIN,
            uiPINLen,
            uiKEKInfo,
            uiKeyType,
            uiPlainKey,
            uiPKLen,
            pCipherKey,
            &pCKLen)) != SDR_OK) {
        throwSDFException(env, rv);
        goto cleanup;
    }

    encKeyArr = (*env)->NewByteArray(env, pCKLen);
    (*env)->SetByteArrayRegion(env, encKeyArr, 0, pCKLen, pCipherKey);

cleanup:
    if (uiKEKInfo) {
        SDF_ReleaseKEKInfo(uiKEKInfo);
    }
    if (pin) {
        (*env)->ReleaseByteArrayElements(env, pin, uiPIN, 0);
    }
    // cannot release bytes here, SDF_HW_EncryptSecretkeyWithoutPlaintext has been free the uiPlainKey.
    /*if (plainKey) {
        (*env)->ReleaseByteArrayElements(env, plainKey, uiPlainKey, 0);
    }*/
    return encKeyArr;
}
