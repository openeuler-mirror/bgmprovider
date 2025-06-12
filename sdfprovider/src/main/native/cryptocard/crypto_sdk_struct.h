#ifndef CRYPTOCARDSDK_CRYPTO_SDK_STRUCT_H
#define CRYPTOCARDSDK_CRYPTO_SDK_STRUCT_H

#ifdef __cplusplus
extern "C" {
#endif
#define VF_UUID_LENGTH 36  //虚机uuid的长度
#define HMAC_VALUE_LENGTH 32  //hmac结果长度
#define KEK_ID_LENGTH 36  // KEK ID长度
#define REGION_ID_LENGTH 32  // Region ID长度
#define CDP_ID_LENGTH 32  // 集群ID长度
#define KEK_DEFAULT_IV_LEN 16  // KEK默认IV长度
#define NATURE_BUF_MAX_LEN 256  // KEK属性的最大长度
#define SM2_KEY_BUF_LEN 32  // SM2的私钥属性长度
#define SM9_KEY_BUF_LEN 32  // SM9的私钥属性长度
#define RSA_KEY_BUF_LEN 512  // RSA的公钥属性长度
#define ECC_KEY_BUF_LEN 66  // 66的私钥属性长度
#define SM2_OLD_C_SIZE 136  // SM2 C参照GM/T 0018.2008
#define CARD_TASK_DATA_SIZE 512  // 密码卡触发的任务数据最大长度
#define SSL_PRF_BUF_LENGTH 32  // SSL密钥派生标签大小
#define SSL_PRF_LABEL_BUF_LENGTH 24  // SSL密钥派生标签大小
#define LABAL_MS "master secret"  // SSL密钥派生标签
#define LABAL_KE "key expansion"  // SSL密钥派生标签
#define LABAL_CF "client finished"  // SSL密钥派生标签
#define LABAL_SF "server finished"  // SSL密钥派生标签
#define LABAL_EMS "extended master secret"  // SSL密钥派生标签

// 用户需要
#define IV_MAX_LEN 16  // 最大IV长度
#define AUTH_IV_MAX_LEN 32  // 鉴权最大IV长度
#define MAC_MAX_LEN 64  // 最大mac长度

// 结构体
typedef struct DeviceInfo_st {
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DeviceBaseInfo;

typedef struct KEKInfo_st {
    unsigned char kekId[KEK_ID_LENGTH];
    unsigned char regionId[REGION_ID_LENGTH];
    unsigned char cdpId[CDP_ID_LENGTH];  //集群ID
} KEKInfo, *KEKInfoHandle;

typedef struct KEKNature_st {
    unsigned int pidLen;  //租户ID多值合计长度
    unsigned char* projectId;  //租户ID, 单个大小32字节，多值
    unsigned int didLen;  //租户ID多值合计长度
    unsigned char* domainId;  //租户ID, 单个大小32字节，多值
    unsigned int ridLen;  //RegionID多值合计长度
    unsigned char* regionId;  //regionId, 单个大小32字节，多值
    unsigned int cidLen;  //集群ID多值合计长度
    unsigned char* cdpId;  //集群ID, 单个大小32字节，多值
    unsigned int aliasLen;  //别名长度，不涉及时传0即可
    unsigned char alias[NATURE_BUF_MAX_LEN];  // 别名-可选，不涉及时传NULL即可
    unsigned int tagsLen;  //标签长度，不涉及时传0即可
    unsigned char* tags;  // 标签-可选，不涉及时传NULL即可
    unsigned int descriptionLen;  //密钥描述长度，不涉及时传0即可
    unsigned char description[NATURE_BUF_MAX_LEN];  //密钥描述-可选，不涉及时传NULL即可
} KEKNature, *KEKNatureHandle;

typedef struct KeyMaterials_st {
    void* keyHandle;  //密文密钥
    char label[SSL_PRF_LABEL_BUF_LENGTH];  // 支持的标签：LABAL_MS "master secret",
    // LABAL_KE "key expansion"
    // LABAL_CF "client finished"
    // LABAL_SF "server finished"
    // LABAL_EMS "extended master secret"
    unsigned int labelLength;
    unsigned char serverRandom[SSL_PRF_BUF_LENGTH];
    unsigned int serverRandomLen;
    unsigned char clientRandom[SSL_PRF_BUF_LENGTH];
    unsigned int clientRandomLen;
    unsigned char sslHash[SSL_PRF_BUF_LENGTH];  //派生扩展主密钥或结束消息时使用
    unsigned int sslHashLen;  //派生扩展主密钥或结束消息时使用
} KeyMaterials;

typedef struct WorkKeyLen_st {
    unsigned int macKeyLenClient;  //待派生的客户端计算MAC的密钥长度
    unsigned int macKeyLenServer;  //待派生的服务端计算MAC的密钥长度
    unsigned int encKeyLenClient;  //待派生的客户端加解密的密钥长度
    unsigned int encKeyLenServer;  //待派生的服务端加解密的密钥长度
    unsigned int macKeyTypeClient;  //待派生的客户端计算MAC的密钥类型
    unsigned int macKeyTypeServer;  //待派生的服务端计算MAC的密钥类型
    unsigned int encKeyTypeClient;  //待派生的客户端加解密的密钥类型
    unsigned int encKeyTypeServer;  //待派生的服务端加解密的密钥类型
    unsigned int ivClient;
    unsigned int ivServer;
} WorkKeyLen;

typedef struct SM2PublicKey_st {
    unsigned int bits;
    unsigned char x[SM2_KEY_BUF_LEN];
    unsigned char y[SM2_KEY_BUF_LEN];
} SM2PublicKey;

typedef struct RSAPublicKey_st {
    unsigned int bits;
    unsigned char m[RSA_KEY_BUF_LEN];
    unsigned char e[RSA_KEY_BUF_LEN];
} RSAPublicKey;

typedef struct SM2PrivateKey_st {
    unsigned int bits;
    unsigned char D[SM2_KEY_BUF_LEN];  // 加密返回
} SM2PrivateKey;

typedef struct SM2Cipher_st {
    unsigned char x[SM2_KEY_BUF_LEN];
    unsigned char y[SM2_KEY_BUF_LEN];
    unsigned char M[SM2_KEY_BUF_LEN];
    unsigned int L;
    unsigned char C[SM2_OLD_C_SIZE];
} SM2Cipher;

typedef struct SM2Signature_st {
    unsigned char r[SM2_KEY_BUF_LEN];
    unsigned char s[SM2_KEY_BUF_LEN];
} SM2Signature;

typedef struct SM9EncMasterPublicKey_st {
    unsigned int bits;
    unsigned char x[SM9_KEY_BUF_LEN];
    unsigned char y[SM9_KEY_BUF_LEN];
} SM9EncMasterPublicKey;

typedef struct SM9SignMasterPublicKey_st {
    unsigned int bits;
    unsigned char xa[SM9_KEY_BUF_LEN];  //X低维坐标
    unsigned char xb[SM9_KEY_BUF_LEN];  //X高维坐标
    unsigned char ya[SM9_KEY_BUF_LEN];  //Y低维坐标
    unsigned char yb[SM9_KEY_BUF_LEN];  //Y高维坐标
} SM9SignMasterPublicKey;

typedef struct ECCPublicKey_st {
    unsigned int bit;  //对应256，384，521
    unsigned char x[ECC_KEY_BUF_LEN];
    unsigned char y[ECC_KEY_BUF_LEN];
    unsigned char z[ECC_KEY_BUF_LEN];
} ECCPublicKey;

typedef struct ECCPrivateKey_st {
    unsigned int bits;
    unsigned char D[ECC_KEY_BUF_LEN];
} ECCPrivateKey;

typedef struct ECCSignature_st {
    unsigned char r[ECC_KEY_BUF_LEN];
    unsigned char s[ECC_KEY_BUF_LEN];
} ECCSignature;

typedef enum { CTX_TYPE_SYMM = 0, CTX_TYPE_HASH = 1, CTX_TYPE_HMAC = 2 } ContextType;

typedef enum { MODE_CLOUD = 1, MODE_UNIVERSAL = 2 } SceneMode;

typedef enum {
    DATA_KEY_SM2 = 0,
    DATA_KEY_RSA = 1,
    DATA_KEY_ECC = 2,
    DATA_KEY_SM4 = 3,
    DATA_KEY_SM1 = 4,
    DATA_KEY_SM7 = 5,
    DATA_KEY_AES = 6,
    DATA_KEY_3DES = 7,
    DATA_KEY_HMAC_SM3 = 8,
    DATA_KEY_HMAC_SHA1 = 9,
    DATA_KEY_HMAC_SHA224 = 10,
    DATA_KEY_HMAC_SHA256 = 11,
    DATA_KEY_HMAC_SHA384 = 12,
    DATA_KEY_HMAC_SHA512 = 13,
    DATA_KEY_SM9_MASTER_SIGN = 14,
    DATA_KEY_SM9_MASTER_ENC = 15,
    DATA_KEY_SM9_USER_SIGN = 16,
    DATA_KEY_SM9_USER_ENC = 17,
} DataKeyType;

typedef enum {
    ALG_SM3 = 1,
    ALG_SHA1 = 2,
    ALG_SHA224 = 3,
    ALG_SHA256 = 4,
    ALG_SHA384 = 5,
    ALG_SHA512 = 6,
    ALG_MD5 = 7,
} HashAlgId;

typedef enum { ALG_SM1 = 1, ALG_SM4 = 2, ALG_SM7 = 3, ALG_AES = 4, ALG_3DES = 5 } SymAlgId;

typedef enum {
    ALG_RSA = 1,
    ALG_SM2 = 2,
    ALG_SM9 = 3,
    ALG_ECC = 4,
} ASymAlgId;

typedef enum {
    ALG_SM1_MAC = 1,
    ALG_SM4_MAC = 2,
    ALG_SM7_MAC = 3,
    ALG_AES_MAC = 4,
    ALG_DES_MAC = 5,
    ALG_3DES_MAC = 6
} MacAlgId;

typedef enum {
    ALG_MODE_ECB = 1,
    ALG_MODE_CBC = 2,
    ALG_MODE_CFB = 3,
    ALG_MODE_OFB = 4,
    ALG_MODE_GCM = 5,
    ALG_MODE_CCM = 6,
    ALG_MODE_XTS = 7,
    ALG_MODE_CTR = 8
} AlgModeType;

typedef enum {
    DEVICE_PUBLIC_KEY = 1,
    CDP_DATA_PUBLIC_KEY = 2,
    CDP_KEK_PUBLIC_KEY = 3,
} PublicKeyType;

typedef enum {
    PAD_NO = 0,
    PAD_PKCS7 = 1,
} PadMode;

typedef enum {
    VF_KEK_KEY = 1,
    VF_AUTH_KEY = 2,
    VF_UUID_INFO = 3,
} VFKeyInfoType;

typedef struct CardTask_st {
    unsigned int taskType;  // 密码卡任务类型
    unsigned int dataLen;  // 密码卡任务数据长度
    unsigned char data[CARD_TASK_DATA_SIZE];  // 任务参数：按类型截断
} CardTask;

typedef int (*CardTaskCallback)(CardTask* cardTask);

typedef struct TagKeyRotationStatus {
    int keyRotationEnabled;
    int rotationInterval;
    int numberOfRotations;
    long lastRotationTime;
} KeyRotationStatus;

typedef struct VFAuthStruct_st {
    unsigned char uuid[VF_UUID_LENGTH];
    unsigned int keyIndex;
    unsigned char pubKey[sizeof(SM2PublicKey) * 2];
    unsigned char hmac[HMAC_VALUE_LENGTH * 2];
} VFAuthStruct, *AuthKeyHandle;

#ifdef __cplusplus
}
#endif

#endif  //CRYPTOCARDSDK_CRYPTO_SDK_STRUCT_H
