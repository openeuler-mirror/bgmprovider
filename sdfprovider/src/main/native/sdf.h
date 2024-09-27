/*
* File: swsds.h
* Copyright (c) SWXA 2009
*
* v1.00.0001  2009.07.15   yaahao
*/

#ifndef _SW_SDS_H_
#define _SW_SDS_H_ 1

#ifdef __cplusplus
extern "C"{
#endif

#define GMT0018_2012		1

/*数据类型定义*/
typedef char				SGD_CHAR;
typedef char				SGD_INT8;
typedef short				SGD_INT16;
typedef int					SGD_INT32;
typedef long long			SGD_INT64;
typedef unsigned char		SGD_UCHAR;
typedef unsigned char		SGD_UINT8;
typedef unsigned short		SGD_UINT16;
typedef unsigned int		SGD_UINT32;
typedef unsigned long long	SGD_UINT64;
typedef unsigned int		SGD_RV;
typedef void*				SGD_OBJ;
typedef int					SGD_BOOL;
typedef void*				SGD_HANDLE;
//typedef void*				SYSCIPHER_HANDLE;
//typedef void* 				HASH_HANDLE_Ex;
/*设备信息*/
typedef struct DeviceInfo_st
{
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;


/*设备信息*/
typedef struct DeviceInfoAll_st{
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];    //国密认证型号
    unsigned char DeviceSerial[16];
    unsigned int  DeviceVersion;
    unsigned int  StandardVersion;
    unsigned int  AsymAlgAbility[2];
    unsigned int  SymAlgAbility;
    unsigned int  HashAlgAbility;
    unsigned int  BufferSize;
    unsigned char SW_Serial[28];     //内部型号

    unsigned int ConfigFlag;
    unsigned int ConfigKeyNum_RSA;
    unsigned int ConfigKeyNum_ECC;
    unsigned int ConfigKeyNum_KEK;
    unsigned int ConfigKeyNum_SM9;
    //unsigned char Reserve[16];
    //unsigned char ConfigDelay[16];
    unsigned int FlashSpace;
    unsigned int SRAMSpace;
    unsigned int DestroyKeyFlag;
    unsigned int ConfigVFNum;
    unsigned char ConfigDelay[16];
    unsigned char Reserve2[128 - 52];
}DEVICEINFOALL;

/*RSA密钥*/
#define RSAref_MAX_BITS    2048
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKey_st
{
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st
{
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

#define ExRSAref_MAX_BITS		4096
#define ExRSAref_MAX_LEN		((ExRSAref_MAX_BITS + 7) / 8)
#define ExRSAref_MAX_PBITS		((ExRSAref_MAX_BITS + 1) / 2)
#define ExRSAref_MAX_PLEN		((ExRSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKeyEx_st
{
    unsigned int  bits;
    unsigned char m[ExRSAref_MAX_LEN];
    unsigned char e[ExRSAref_MAX_LEN];
} RSArefPublicKeyEx;

typedef struct RSArefPrivateKeyEx_st
{
    unsigned int  bits;
    unsigned char m[ExRSAref_MAX_LEN];
    unsigned char e[ExRSAref_MAX_LEN];
    unsigned char d[ExRSAref_MAX_LEN];
    unsigned char prime[2][ExRSAref_MAX_PLEN];
    unsigned char pexp[2][ExRSAref_MAX_PLEN];
    unsigned char coef[ExRSAref_MAX_PLEN];
} RSArefPrivateKeyEx;

typedef struct
{
    unsigned int R2p[64];
    unsigned int R2q[64];
    unsigned int R2n[128];
    unsigned int pp[8];
    unsigned int qq[8];
    unsigned int nn[8];
} R_RSA_EXTEND_C_P1_P2_Ex;

typedef struct RSACipherKey_st
{
    RSArefPrivateKeyEx RSAPrivateKeyEx;
    R_RSA_EXTEND_C_P1_P2_Ex EXTEND_C;
} RSACipherKey, *RSACipherKeyHandle;

#ifndef GMT0018_2012
/*2008版密码设备应用接口规范ECC密钥数据结构定义*/

#define ECCref_MAX_BITS			256
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN	136

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    unsigned int  bits;
    unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*ECC 密文*/
typedef struct ECCCipher_st
{
	unsigned int  clength;  //C的有效长度
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char C[ECCref_MAX_CIPHER_LEN];
    unsigned char M[ECCref_MAX_LEN];
} ECCCipher;

/*ECC 签名*/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
} ECCSignature;
#else
/*2012版密码设备应用接口规范ECC密钥数据结构定义*/

#define ECCref_MAX_BITS					512
#define ECCref_MAX_LEN					((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN			136

typedef struct ECCrefPublicKey_st
{
    unsigned int  bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    unsigned int  bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*ECC 密文*/
typedef struct ECCCipher_st
{
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int  L;
    unsigned char C[1];
} ECCCipher;

/*ECC 签名*/
typedef struct ECCSignature_st
{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;
#endif

typedef struct ECCrefKeyPair_st
{
    ECCrefPublicKey SM2PubKey;
    ECCrefPrivateKey SM2PriKey;
} ECCrefKeyPair;

#define SM9ref_MAX_BITS		256
#define SM9ref_MAX_LEN		((SM9ref_MAX_BITS+7) / 8)

#define MAX_SM9_ID_LENGTH					128

typedef struct SM9refSignMasterPrivateKey_st
{
    unsigned int bits;
    unsigned char s[SM9ref_MAX_LEN];
} SM9refSignMasterPrivateKey;

typedef struct SM9refSignMasterPublicKey_st
{
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
    unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
    unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
    unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
} SM9refSignMasterPublicKey;

typedef struct SM9refSignMasterKeyPair_st
{
    SM9refSignMasterPrivateKey MasterPrivateKey;
    SM9refSignMasterPublicKey MasterPublicKey;
    unsigned char MasterKeyPairG[1536];
} SM9refSignMasterKeyPair;

typedef struct SM9refEncMasterPrivateKey_st
{
    unsigned int bits;
    unsigned char s[SM9ref_MAX_LEN];
} SM9refEncMasterPrivateKey;

typedef struct SM9refEncMasterPublicKey_st
{
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9refEncMasterPublicKey;

typedef struct SM9refEncMasterKeyPair_st
{
    SM9refEncMasterPrivateKey MasterPrivateKey;
    SM9refEncMasterPublicKey MasterPublicKey;
    unsigned char MasterKeyPairG[384];
} SM9refEncMasterKeyPair;

typedef struct SM9refPublicUserID_st
{
    unsigned int IDLen;
    unsigned char ID[MAX_SM9_ID_LENGTH];
} SM9refPublicUserID;

typedef struct SM9refSignUserPrivateKey_st
{
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9refSignUserPrivateKey;

typedef struct SM9refSignUserKeyPair_st
{
    SM9refSignUserPrivateKey PrivateKey;
    SM9refPublicUserID PublicUserID;
} SM9refSignUserKeyPair;

typedef struct SM9refEncUserPrivateKey_st
{
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
    unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
    unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
    unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
} SM9refEncUserPrivateKey;

typedef struct SM9refEncUserKeyPair_st
{
    SM9refEncUserPrivateKey PrivateKey;
    SM9refPublicUserID PublicUserID;
} SM9refEncUserKeyPair;

typedef struct SM9Signature_st
{
    unsigned char h[SM9ref_MAX_LEN];
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9Signature;

typedef struct SM9Cipher_st
{
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
    unsigned char h[SM9ref_MAX_LEN];
    unsigned int L;
    unsigned char C[1024];
} SM9Cipher;

typedef struct SM9refKeyPackage_st
{
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9refKeyPackage;

typedef struct SM9AgreementParam_st
{
    SGD_UINT32 nHandleFlag;
    unsigned char pucRandom[32];
    unsigned int uiRandomLength;
    unsigned char pucRA[64];
    unsigned int uiRALength;
} SM9AgreementParam;

//华为云密码卡相关
//华为SM2密钥256位结构体定义
/*ECC密钥*/
#define ECCref_MAX_BITS_HW				256
#define ECCref_MAX_LEN_HW				((ECCref_MAX_BITS_HW+7) / 8)
#define ECCref_MAX_CIPHER_LEN_HW			136

typedef struct ECCrefCurveParam_HW_st
{
    unsigned char p[ECCref_MAX_LEN_HW];	//素数p
    unsigned char a[ECCref_MAX_LEN_HW];	//参数a
    unsigned char b[ECCref_MAX_LEN_HW];	//参数b
    unsigned char gx[ECCref_MAX_LEN_HW];	//参数Gx: x coordinate of the base point G
    unsigned char gy[ECCref_MAX_LEN_HW];	//参数Gy: y coordinate of the base point G
    unsigned char n[ECCref_MAX_LEN_HW];	//阶N: order n of the base point G
    unsigned int  len;					//参数位长Len，Len必须为160、192、224或256
} ECCrefCurveParam_HW;

typedef struct ECCrefPublicKey_HW_st
{
    unsigned int  bits;
    unsigned char x[ECCref_MAX_LEN_HW];
    unsigned char y[ECCref_MAX_LEN_HW];
} ECCrefPublicKey_HW;

typedef struct ECCrefPrivateKey_HW_st
{
    unsigned int  bits;
    unsigned char D[ECCref_MAX_LEN_HW];
} ECCrefPrivateKey_HW;

/*ECC 密文*/
typedef struct ECCCipher_HW_Ex_st
{
    unsigned char x[ECCref_MAX_LEN_HW];
    unsigned char y[ECCref_MAX_LEN_HW];
    unsigned char M[ECCref_MAX_LEN_HW];
    unsigned int  L;  //C的有效长度
    unsigned char C[1];
} ECCCipher_HW_Ex;

/*ECC 签名*/
typedef struct ECCSignature_HW_st
{
    unsigned char r[ECCref_MAX_LEN_HW];
    unsigned char s[ECCref_MAX_LEN_HW];
} ECCSignature_HW;
/*
数据结构struct swxa_crypto_data_structure中各成员变量含义 :
(1)key[64] : 密文密钥，最多为64字节；
(2)keyid[8] : 密钥id，大小为32字节；（现在只能使用dek id，dek id存放到keyid[0]里，且与生成密文密钥使用的keynum值相同）
(3)keylen : 密文密钥长度；
(4)calibration : 密文密钥校验值；
(5)algorithm : 使用的密码算法，使用国标标识如SGD_SM4_CBC、SGD_SM4_ECB等；
(6)version : 版本号；
(7)reserved[22] : 预留的空间。
*/

//DEK密钥结构(可支持对称、SM2、ECC、SM9密钥)
typedef struct SysCKey_st {
    unsigned char key[64];
    unsigned char keyid[32];
    unsigned char RegionID[32];
    unsigned char CdpID[32];
    unsigned int keylen;
    unsigned char calibration[8];
    unsigned int algorithm;
    unsigned int version;
    unsigned char dek_pin[16];
    unsigned char dekiv[16];
    unsigned int keytype;
    unsigned char reserved[294];
}SysCKey, * SysCKeyHANDLE;

#define HW_KEKPIN_LENGTH	16

//DEK密钥结构（可支持RSA密钥）
typedef struct RSACKey_st {
    unsigned char key[4096];
    unsigned char keyid[32];
    unsigned char RegionID[32];
    unsigned char CdpID[32];
    unsigned int keylen;
    unsigned char calibration[8];
    unsigned int algorithm;
    unsigned int version;
    unsigned char dek_pin[HW_KEKPIN_LENGTH];
    unsigned int dek_pinlen;
    unsigned char dekiv[16];
    unsigned int keytype;
    unsigned char reserved[356];
}RSACKey, * RSACKeyHANDLE;

/*华为*/
typedef struct HMACKey_st {
    unsigned char key[3072];
    unsigned char keyid[32];
    unsigned char RegionID[32];
    unsigned char CdpID[32];
    unsigned int keylen;
    unsigned char calibration[8];
    unsigned int algorithm;
    unsigned int version;
    unsigned char dek_pin[16];
    unsigned int dek_pinlen;
    unsigned char dekiv[16];
    unsigned int keytype;
    unsigned char reserved[356];
}HMACKey, *HMACKeyHANDLE;

typedef struct C_SM2Pairs_st
{
    SysCKey SM2PriCKey;
    unsigned char SM2PubKey[132];
    unsigned int PubkeyLen;
} C_SM2Pairs;

//虚拟卡资源状态
typedef struct VirtualResINFO_st{
    unsigned int uiVFnum;//返回虚拟设备数
    unsigned char VFID[64];//虚拟卡设备号;
    unsigned long long Ultime;//返回设备运行时间
    unsigned int pPKTime;//返回设备响应峰值
    float pLoad;//返回设备负载，数组元素值范围0.00-1.00。负载统计方式为：同时周期内密码卡工作时间与周期的比值。
} VirtualResINFO;

//物理卡资源状态
typedef struct PhysicalResINFO_st{
    unsigned int pNum;//返回密码卡物理卡个数
    unsigned int VoltageType_1_2;//主板电压1.2V
    unsigned int VoltageType_3_3;// 主板电压3.3V
    unsigned int VoltageType_12; //主板电压12V
    unsigned int VoltageType_batt; //密码卡内电池电压
    float pTemper;//返回温度
    float pPower;//返回功耗
    unsigned int pKeyCapacity;//返回密钥存储区总容量
    unsigned int pUseCapacity;//返回密钥存储区已使用容量
    float pLifespan;//返回寿命比值，元素值范围0.00-1.00
    unsigned int pHelStatusPF;//设物理设备健康状态，0-不健康，1-健康
    unsigned char sFirmware[32];//返回密码卡固件版本
    unsigned char sLibraryVersion[16];//返回接口库版本
    DEVICEINFO pstDeviceInfo;//返回密码卡设备基本信息
} PhysicalResINFO;

//资源上报回调结构
typedef struct CallbackPullResINFO_st {
    int (*Callback_PullResINFO)(PhysicalResINFO *uiPResINFO, VirtualResINFO *uiVResINFO);
} CallbackPullResINFO;

//日志详情
typedef struct LOGDATAINFO_st{
    unsigned char logtime[24];//日志时间
    unsigned char module[16];//产生日志的模块
    unsigned int ThreadId;//线程ID
    unsigned char loglevel[16];//日志等级。输出“Error”、“Warning”、“Info”、“Trace”
    unsigned char logmesg[256];//日志信息
    unsigned char SrcFileName[128];//产生日志的源码文件名
    unsigned int SrcFileLine;//产生日志的源码文件行号
} LOGDATAINFO;

/*
typedef struct HMAC_st
{
	unsigned int AlgID;
	unsigned int BlockLength;
	unsigned char ucKey_OPad[256];
} HMAC_INFO, *HMAC_HANDLE;
*/
/*
typedef struct _SYSCIPHER_INFO_ {
	SGD_UINT32	AlgID;
	SGD_HANDLE KeyHandle;
	SGD_UINT32   nBlockkLen;
	SGD_UCHAR	sIV[32];
	SGD_UINT32	nIVLen;
	SGD_UCHAR	sRemain[32];
	SGD_UINT32	nRemainLen;
	SGD_UCHAR	pucMAC[32];
	SGD_UINT32   pucMACLen;
	SGD_UINT32   PadFlag;
}SYSCIPHER_INFO, *SYSCIPHER_HANDLE;
*/
/*
typedef struct HashHandle_Ex_st
{
	SGD_UINT32 nAlgID;
	SGD_UINT32 nCardNo;
	SGD_UCHAR HASH_CONTEXT[8544];
	SGD_UINT32 nAlgSel;	//Flag
} HASH_INFO_Ex, *HASH_HANDLE_Ex;
*/

typedef struct KEKInfo_st {
    unsigned char KEKID[32];//KEK密钥ID
    unsigned char RegionID[32];//
    unsigned char CdpID[32];//集群ID
}KEKInfo, * KEKInfoHANDLE;

typedef struct KEKCIPHER_st
{
    unsigned char KEKID[32];//KEK密钥ID
    unsigned char Region[32];//RegionID
    unsigned char EnvelopedKey [180];//数字信封
    unsigned int CipherLen;//KEK密文长度
    unsigned char *KEKCipher; //KEK密文
    unsigned char HMACValue[32];//KEK明文HAMC校验值（计算整个密钥）
}KEKCIPHER, KEKCIPHERHANDLE;

typedef struct KEKNature_st {
    unsigned char *project_id; //租户ID, 单个大小32字节，多值，
    unsigned int PIDLen; //租户ID多值合计长度
    unsigned char *domian_id;//租户ID, 单个大小32字节，多值
    unsigned int DIDLen; //租户ID多值合计长度
    unsigned char *Region_id;//RegionID, 单个大小32字节，多值
    unsigned int RIDLen; //RegionID多值合计长度
    unsigned char *Cdp_id;//集群ID, 单个大小32字节，多值
    unsigned int CIDLen; //集群ID多值合计长度
    unsigned char *alias;// 别名-可选，不涉及时传NULL即可
    unsigned int aliasLen;
    unsigned char *tags; // 标签-可选，不涉及时传NULL即可
    unsigned int tagsLen;//标签长度，不涉及时传0即可
    unsigned char *description;//密钥描述-可选，不涉及时传NULL即可
    unsigned int descriptionLen;
}KEKNature,*KEKNatureHANDLE;

typedef struct GenDEKPara_st {
    unsigned int uiAlgID;//KEK加密明文DEK时的算法模式
    unsigned char IV[16];//初始化向量，当加密模式为CBC、CFB、OFB等时使用，ECB模式传NULL即可
    unsigned int IVLen; //初始化向量长度，当加密模式为CBC、CFB、OFB等时使用，ECB模式传0即可
}DEKProtectPara, *DEKProtectParaHANDLE;


typedef struct CallbackPullKEK_st {
    int (*Callback_PullKEK)( KEKInfo *uiKEKInfo, KEKCIPHER *pucKeyData);
}CallbackPullKEK;


typedef struct CallbackPostKEK_st {
    int (*Callback_PostKEK)( KEKInfo *uiKEKInfo, KEKCIPHER *pucKeyData);
}CallbackPostKEK;


typedef struct ALARMINFO_st {
    unsigned char id[32];//UUID，密码卡序列号+报警在卡中的序号
    unsigned char name[16];//告警名称
    unsigned int level;//告警级别，3：“critical”为紧急；2：“major”为严重；1：minjor为一般；0：“waring”为提示。输出为critical等
    unsigned char create_time[32];//告警产生时间，格式如2022/11/20 12:30 GMT+8:00
    unsigned char cancel_time[32];//告警消除时间，格式如2022/11/20 12:30 GMT+8:00
    unsigned char cancel_type[4];//告警消除类型：ADAC:自动消除；ADMC：手动消除
    unsigned int canceled;//告警状态是否已消除，1：已消除；0：未消除
    unsigned char suggestion[32];//告警处置建议
    unsigned char description[32];//告警的详细描述
    unsigned int notice;//实时刷新上报云管，1：已上报云管告警；0：未上报云管告警
    unsigned int report_time;//告警累计上报次数
    unsigned char report_attch[32];//告警附加信息
} ALARMINFO,* ALARMINFOHANDLE;

typedef struct CallbackPullALARMINFO_st {
    int (*Callback_PullALARMINFO)(ALARMINFO *uiAlarms);
} CallbackPullALARMINFO;

typedef struct CallbackCancelALARMINFO_st {
    int (*Callback_CancelALARMINFO)(ALARMINFO *uiAlarms);
}CallbackCancelALARMINFO;

typedef struct KeyMaterials_st
{
    unsigned char *uiCHashKey;//密文密钥。当预主密钥派生主密钥时，此项为密文预主密钥；当主密钥派生工作密钥时，此项为密文主密钥
    char *uiLabel;//常量字符串
    unsigned int uiLabelLength; //常量字符串长度
    unsigned char *uiServerRandom;//服务端随机数
    unsigned int uiSRLen; //服务端随机数长度
    unsigned char *uiClientRandom; //客户端随机数
    unsigned int uiCRLen; //客户端随机数
    unsigned char *uiSessionHash;//派生扩展主密钥时使用
    unsigned int uiSHLen;//派生扩展主密钥时使用
    unsigned char *uiHandshakeHash;//派生结束消息时使用
    unsigned int uiHHLen;//派生结束消息时使用
}KeyMaterials;

//KeyMaterials中uiLabel可支持如下输入
#define LABAL_MS			"master secret"
#define LABAL_KE			"key expansion"
#define LABAL_CF			"client finished"
#define LABAL_SF			"server finished"
#define LABAL_EMS			"extended master secret"

typedef struct WorkKeyLen_st {
    unsigned int ClientMACKeyLen;//待派生的客户端计算MAC的密钥长度
    unsigned int ServerMACKeyLen; //待派生的服务端计算MAC的密钥长度
    unsigned int ClientSysKeyLen;//待派生的客户端加解密的密钥长度
    unsigned int ServerSysKeyLen; //待派生的服务端加解密的密钥长度
    unsigned int ClientIVLen; //待派生的客户端IV长度
    unsigned int ServerIVLen; //待派生的服务端IV长度
}KEYLEN, *KEYLENHANDLE;


typedef struct DerivedKey_st {
    SysCKey ClientMACKey;// 派生的客户端计算MAC的密文密钥
    SysCKey ServerMACKey;// 派生的服务端计算MAC的密文密钥
    SysCKey ClientDataKey;// 派生的客户端加解密数据的密文密钥
    SysCKey ServerDataKey;// 派生的服务端加解密数据的密文密钥
    unsigned char ClientIV[16];// 派生的客户端初始化向量
    unsigned char ServerIV[16];// 派生的服务端初始化向量
} DerivedKey, * DERIVEDHANDLE;


typedef struct ReportAddrList_st {
    unsigned char *uiWaringReportAddr;//告警上报地址
    unsigned int uiWRALen;// 告警上报地址长度
    unsigned char *uiResourceReportAddr;// 资源状态上报地址
    unsigned int uiRRALen;// 资源状态上报地址长度
    unsigned char *uiLogfileAddr;// 日志存储路
    unsigned int uiLALen;// 日志存储路长度
} ReportAddrList, * ReportAddrListHANDLE;

typedef struct KEKStaus_st {
    unsigned char KEKID[32];//KEKID
    unsigned int KeyStaus;//密钥状态：启用，禁用，删除中。禁用、删除中两种状态下不具备加密、解密功能
    unsigned int ReFlag;//轮转标志：轮转，非轮状，实际使用1B
    unsigned int SyncFlag;//启用同步，禁止同步
    unsigned int KeySize;//整个Key的大小
    unsigned int Version;//密钥版本
    unsigned int DIDnum;
    unsigned char* DomianID;//存在多值情况，单个32字节
    unsigned int PIDnum;
    unsigned char* ProjectID;//存在多值情况，单个32字节
    unsigned int RIDnum;
    unsigned char* RegionID;//存在多值情况，单个32字节
}KEKStaus, * KEKStausHANDLE;

/*常量定义*/
//#define MAX_KEK_COUNT					100
//#define MAX_KEK_COUNT					500
#define MAX_KEK_COUNT					2048
//#define MAX_RSA_KEY_PAIR_COUNT			100
#define MAX_RSA_KEY_PAIR_COUNT			1024
//#define MAX_ECC_KEY_PAIR_COUNT			100
#define MAX_ECC_KEY_PAIR_COUNT			2048

//#define MAX_KEY_INFO_COUNT				500
#define MAX_KEY_INFO_COUNT				1024

#define USER_PIN_LENGTH					8    //IC卡PIN口令

#define MAX_DATA_LENGTH					65536
#define MAX_DATA_KB_LENGTH_STR			"64K"

#define KEKIDLen 32

#define LABAL_MS			"master secret"
#define LABAL_KE			"key expansion"
#define LABAL_CF			"client finished"
#define LABAL_SF			"server finished"
#define LABAL_EMS			"extended master secret"

#define	HW_SM2						0
#define	HW_RSA						1
#define	HW_ECC						2
#define	HW_SM9						3
#define	HW_SYM						4
#define	HW_HMAC						5
#define	HW_TLS						6

#define SGD_TRUE		0x00000001
#define SGD_FALSE		0x00000000
#define PAD				1
#define NOPAD			0

/*算法标识*/

#ifndef GMT0018_2012
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
#define SGD_SM1_CTR		0x00000120

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
#define SGD_SSF33_CTR	0x00000220

#define SGD_AES_ECB		0x00000401
#define SGD_AES_CBC		0x00000402
#define SGD_AES_CFB		0x00000404
#define SGD_AES_OFB		0x00000408
#define SGD_AES_MAC		0x00000410
#define SGD_AES_CTR		0x00000420

#define SGD_3DES_ECB	0x00000801
#define SGD_3DES_CBC	0x00000802
#define SGD_3DES_CFB	0x00000804
#define SGD_3DES_OFB	0x00000808
#define SGD_3DES_MAC	0x00000810
#define SGD_3DES_CTR	0x00000820

#define SGD_SMS4_ECB	0x00002001
#define SGD_SMS4_CBC	0x00002002
#define SGD_SMS4_CFB	0x00002004
#define SGD_SMS4_OFB	0x00002008
#define SGD_SMS4_MAC	0x00002010
#define SGD_SMS4_CTR	0x00002020

#define SGD_SM4_ECB		0x00002001
#define SGD_SM4_CBC		0x00002002
#define SGD_SM4_CFB		0x00002004
#define SGD_SM4_OFB		0x00002008
#define SGD_SM4_MAC		0x00002010
#define SGD_SM4_CTR		0x00002020

#define SGD_DES_ECB		0x00004001
#define SGD_DES_CBC		0x00004002
#define SGD_DES_CFB		0x00004004
#define SGD_DES_OFB		0x00004008
#define SGD_DES_MAC		0x00004010
#define SGD_DES_CTR		0x00004020

#define SGD_SM7_ECB		0x00008001
#define SGD_SM7_CBC		0x00008002
#define SGD_SM7_CFB		0x00008004
#define SGD_SM7_OFB		0x00008008
#define SGD_SM7_MAC		0x00008010
#define SGD_SM7_CTR		0x00008020

#define SGD_SM6_ECB		0x00010001
#define SGD_SM6_CBC		0x00010002
#define SGD_SM6_CFB		0x00010004
#define SGD_SM6_OFB		0x00010008
#define SGD_SM6_MAC		0x00010010
#define SGD_SM6_CTR		0x00010020
#else
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
#define SGD_SM1_CTR		0x00000120

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
#define SGD_SSF33_CTR	0x00000220

#define SGD_SMS4_ECB	0x00000401
#define SGD_SMS4_CBC	0x00000402
#define SGD_SMS4_CFB	0x00000404
#define SGD_SMS4_OFB	0x00000408
#define SGD_SMS4_MAC	0x00000410
#define SGD_SMS4_CTR	0x00000420
#define SGD_SMS4_XTS	0x00000440

#define SGD_SM4_ECB		0x00000401
#define SGD_SM4_CBC		0x00000402
#define SGD_SM4_CFB		0x00000404
#define SGD_SM4_OFB		0x00000408
#define SGD_SM4_MAC		0x00000410
#define SGD_SM4_CTR		0x00000420
#define SGD_SM4_XTS		0x00000440

#define SGD_ZUC_EEA3	0x00000801	//ZUC祖冲之机密性算法128-EEA3
#define SGD_ZUC_EIA3	0x00000802	//ZUC祖冲之完整性算法128-EIA3

#define SGD_SM7_ECB		0x00001001
#define SGD_SM7_CBC		0x00001002
#define SGD_SM7_CFB		0x00001004
#define SGD_SM7_OFB		0x00001008
#define SGD_SM7_MAC		0x00001010
#define SGD_SM7_CTR		0x00001020

#define SGD_DES_ECB		0x00002001
#define SGD_DES_CBC		0x00002002
#define SGD_DES_CFB		0x00002004
#define SGD_DES_OFB		0x00002008
#define SGD_DES_MAC		0x00002010
#define SGD_DES_CTR		0x00002020

#define SGD_3DES_ECB	0x00004001
#define SGD_3DES_CBC	0x00004002
#define SGD_3DES_CFB	0x00004004
#define SGD_3DES_OFB	0x00004008
#define SGD_3DES_MAC	0x00004010
#define SGD_3DES_CTR	0x00004020

#define SGD_AES_ECB		0x00008001
#define SGD_AES_CBC		0x00008002
#define SGD_AES_CFB		0x00008004
#define SGD_AES_OFB		0x00008008
#define SGD_AES_MAC		0x00008010
#define SGD_AES_CTR		0x00008020

#define SGD_SM6_ECB		0x00010001
#define SGD_SM6_CBC		0x00010002
#define SGD_SM6_CFB		0x00010004
#define SGD_SM6_OFB		0x00010008
#define SGD_SM6_MAC		0x00010010
#define SGD_SM6_CTR		0x00010020
#endif

#define SGD_RSA			0x00010000
#define SGD_RSA_SIGN	0x00010100
#define SGD_RSA_ENC		0x00010200

#ifndef GMT0018_2012
#define SGD_SM2_1		0x00020100
#define SGD_SM2_2		0x00020200
#define SGD_SM2_3		0x00020400
#else
#define SGD_SM2			0x00020100
#define SGD_SM2_1		0x00020200
#define SGD_SM2_2		0x00020400
#define SGD_SM2_3		0x00020800
#endif

#define SGD_SM3			0x00000001
#define SGD_SHA1		0x00000002
#define SGD_SHA256		0x00000004
#define SGD_SHA512		0x00000008
#define SGD_SHA384		0x00000010
#define SGD_SHA224		0x00000020
#define SGD_MD5			0x00000080

#define SGD_SYMM_ALG_MASK		0xFFFFFF00
#define SGD_SYMM_ALG_MODE_MASK  0x000000FF

#define SGD_ASYMM_ALG_MASK		0xFFFF0000


/*标准错误码定义*/
#define SDR_OK					0x0						   /*成功*/
#define SDR_BASE				0x01000000
#define SDR_UNKNOWERR			(SDR_BASE + 0x00000001)	   /*未知错误*/
#define SDR_NOTSUPPORT			(SDR_BASE + 0x00000002)	   /*不支持*/
#define SDR_COMMFAIL			(SDR_BASE + 0x00000003)    /*通信错误*/
#define SDR_HARDFAIL			(SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE			(SDR_BASE + 0x00000005)    /*打开设备错误*/
#define SDR_OPENSESSION			(SDR_BASE + 0x00000006)    /*打开会话句柄错误*/
#define SDR_PARDENY				(SDR_BASE + 0x00000007)    /*权限不满足*/
#define SDR_KEYNOTEXIST			(SDR_BASE + 0x00000008)    /*密钥不存在*/
#define SDR_ALGNOTSUPPORT		(SDR_BASE + 0x00000009)    /*不支持的算法*/
#define SDR_ALGMODNOTSUPPORT	(SDR_BASE + 0x0000000A)    /*不支持的算法模式*/
#define SDR_PKOPERR				(SDR_BASE + 0x0000000B)    /*公钥运算错误*/
#define SDR_SKOPERR				(SDR_BASE + 0x0000000C)    /*私钥运算错误*/
#define SDR_SIGNERR				(SDR_BASE + 0x0000000D)    /*签名错误*/
#define SDR_VERIFYERR			(SDR_BASE + 0x0000000E)    /*验证错误*/
#define SDR_SYMOPERR			(SDR_BASE + 0x0000000F)    /*对称运算错误*/
#define SDR_STEPERR				(SDR_BASE + 0x00000010)    /*步骤错误*/
#define SDR_FILESIZEERR			(SDR_BASE + 0x00000011)    /*文件大小错误或输入数据长度非法*/
#define SDR_FILENOEXIST			(SDR_BASE + 0x00000012)    /*文件不存在*/
#define SDR_FILEOFSERR			(SDR_BASE + 0x00000013)    /*文件操作偏移量错误*/
#define SDR_KEYTYPEERR			(SDR_BASE + 0x00000014)    /*密钥类型错误*/
#define SDR_KEYERR				(SDR_BASE + 0x00000015)    /*密钥错误*/

/*============================================================*/
/*扩展错误码*/
#define SWR_BASE				(SDR_BASE + 0x00010000)	/*自定义错误码基础值*/
#define SWR_INVALID_USER		(SWR_BASE + 0x00000001)	/*无效的用户名*/
#define SWR_INVALID_AUTHENCODE	(SWR_BASE + 0x00000002)	/*无效的授权码*/
#define SWR_PROTOCOL_VER_ERR	(SWR_BASE + 0x00000003)	/*不支持的协议版本*/
#define SWR_INVALID_COMMAND		(SWR_BASE + 0x00000004)	/*错误的命令字*/
#define SWR_INVALID_PARAMETERS	(SWR_BASE + 0x00000005)	/*参数错误或错误的数据包格式*/
#define SWR_FILE_ALREADY_EXIST	(SWR_BASE + 0x00000006)	/*已存在同名文件*/
#define SWR_SYNCH_ERR			(SWR_BASE + 0x00000007)	/*多卡同步错误*/
#define SWR_SYNCH_LOGIN_ERR		(SWR_BASE + 0x00000008)	/*多卡同步后登录错误*/

#define SWR_SOCKET_TIMEOUT		(SWR_BASE + 0x00000100)	/*超时错误*/
#define SWR_CONNECT_ERR			(SWR_BASE + 0x00000101)	/*连接服务器错误*/
#define SWR_SET_SOCKOPT_ERR		(SWR_BASE + 0x00000102)	/*设置Socket参数错误*/
#define SWR_SOCKET_SEND_ERR		(SWR_BASE + 0x00000104)	/*发送LOGINRequest错误*/
#define SWR_SOCKET_RECV_ERR		(SWR_BASE + 0x00000105)	/*发送LOGINRequest错误*/
#define SWR_SOCKET_RECV_0		(SWR_BASE + 0x00000106)	/*发送LOGINRequest错误*/

#define SWR_SEM_TIMEOUT			(SWR_BASE + 0x00000200)	/*超时错误*/
#define SWR_NO_AVAILABLE_HSM	(SWR_BASE + 0x00000201)	/*没有可用的加密机*/
#define SWR_NO_AVAILABLE_CSM	(SWR_BASE + 0x00000202)	/*加密机内没有可用的加密模块*/

#define SWR_CONFIG_ERR			(SWR_BASE + 0x00000301)	/*配置文件错误*/

/*============================================================*/
/*密码卡错误码*/
#define SWR_CARD_BASE					(SDR_BASE + 0x00020000)			/*密码卡错误码*/
#define SWR_CARD_UNKNOWERR				(SWR_CARD_BASE + 0x00000001)	//未知错误
#define SWR_CARD_NOTSUPPORT				(SWR_CARD_BASE + 0x00000002)	//不支持的接口调用
#define SWR_CARD_COMMFAIL				(SWR_CARD_BASE + 0x00000003)	//与设备通信失败
#define SWR_CARD_HARDFAIL				(SWR_CARD_BASE + 0x00000004)	//运算模块无响应
#define SWR_CARD_OPENDEVICE				(SWR_CARD_BASE + 0x00000005)	//打开设备失败
#define SWR_CARD_OPENSESSION			(SWR_CARD_BASE + 0x00000006)	//创建会话失败
#define SWR_CARD_PARDENY				(SWR_CARD_BASE + 0x00000007)	//无私钥使用权限
#define SWR_CARD_KEYNOTEXIST			(SWR_CARD_BASE + 0x00000008)	//不存在的密钥调用
#define SWR_CARD_ALGNOTSUPPORT			(SWR_CARD_BASE + 0x00000009)	//不支持的算法调用
#define SWR_CARD_ALGMODNOTSUPPORT		(SWR_CARD_BASE + 0x00000010)	//不支持的算法调用
#define SWR_CARD_PKOPERR				(SWR_CARD_BASE + 0x00000011)	//公钥运算失败
#define SWR_CARD_SKOPERR				(SWR_CARD_BASE + 0x00000012)	//私钥运算失败
#define SWR_CARD_SIGNERR				(SWR_CARD_BASE + 0x00000013)	//签名运算失败
#define SWR_CARD_VERIFYERR				(SWR_CARD_BASE + 0x00000014)	//验证签名失败
#define SWR_CARD_SYMOPERR				(SWR_CARD_BASE + 0x00000015)	//对称算法运算失败
#define SWR_CARD_STEPERR				(SWR_CARD_BASE + 0x00000016)	//多步运算步骤错误
#define SWR_CARD_FILESIZEERR			(SWR_CARD_BASE + 0x00000017)	//文件长度超出限制
#define SWR_CARD_FILENOEXIST			(SWR_CARD_BASE + 0x00000018)	//指定的文件不存在
#define SWR_CARD_FILEOFSERR				(SWR_CARD_BASE + 0x00000019)	//文件起始位置错误
#define SWR_CARD_KEYTYPEERR				(SWR_CARD_BASE + 0x00000020)	//密钥类型错误
#define SWR_CARD_KEYERR					(SWR_CARD_BASE + 0x00000021)	//密钥错误
#define SWR_CARD_BUFFER_TOO_SMALL		(SWR_CARD_BASE + 0x00000101)	//接收参数的缓存区太小
#define SWR_CARD_DATA_PAD				(SWR_CARD_BASE + 0x00000102)	//数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式
#define SWR_CARD_DATA_SIZE				(SWR_CARD_BASE + 0x00000103)	//明文或密文长度不符合相应的算法要求
#define SWR_CARD_CRYPTO_NOT_INIT		(SWR_CARD_BASE + 0x00000104)	//该错误表明没有为相应的算法调用初始化函数

//01/03/09版密码卡权限管理错误码
#define SWR_CARD_MANAGEMENT_DENY		(SWR_CARD_BASE + 0x00001001)	//管理权限不满足
#define SWR_CARD_OPERATION_DENY			(SWR_CARD_BASE + 0x00001002)	//操作权限不满足
#define SWR_CARD_DEVICE_STATUS_ERR		(SWR_CARD_BASE + 0x00001003)	//当前设备状态不满足现有操作
#define SWR_CARD_LOGIN_ERR				(SWR_CARD_BASE + 0x00001011)	//登录失败
#define SWR_CARD_USERID_ERR				(SWR_CARD_BASE + 0x00001012)	//用户ID数目/号码错误
#define SWR_CARD_PARAMENT_ERR			(SWR_CARD_BASE + 0x00001013)	//参数错误

//05/06版密码卡权限管理错误码
#define SWR_CARD_MANAGEMENT_DENY_05		(SWR_CARD_BASE + 0x00000801)	//管理权限不满足
#define SWR_CARD_OPERATION_DENY_05		(SWR_CARD_BASE + 0x00000802)	//操作权限不满足
#define SWR_CARD_DEVICE_STATUS_ERR_05	(SWR_CARD_BASE + 0x00000803)	//当前设备状态不满足现有操作
#define SWR_CARD_LOGIN_ERR_05			(SWR_CARD_BASE + 0x00000811)	//登录失败
#define SWR_CARD_USERID_ERR_05			(SWR_CARD_BASE + 0x00000812)	//用户ID数目/号码错误
#define SWR_CARD_PARAMENT_ERR_05		(SWR_CARD_BASE + 0x00000813)	//参数错误

/*============================================================*/
/*读卡器错误*/
#define SWR_CARD_READER_BASE				(SDR_BASE + 0x00030000)	//	读卡器类型错误
#define SWR_CARD_READER_PIN_ERROR			(SWR_CARD_READER_BASE + 0x000063CE)  //口令错误
#define SWR_CARD_READER_NO_CARD				(SWR_CARD_READER_BASE + 0x0000FF01)	 //	IC未插入
#define SWR_CARD_READER_CARD_INSERT			(SWR_CARD_READER_BASE + 0x0000FF02)	 //	IC插入方向错误或不到位
#define SWR_CARD_READER_CARD_INSERT_TYPE	(SWR_CARD_READER_BASE + 0x0000FF03)	 //	IC类型错误

#define HW_KEYHANDLETYPE_SYMM				0
#define HW_KEYHANDLETYPE_HASH				1
#define HW_KEYHANDLETYPE_HMAC				2

/*设备管理类函数*/
SGD_RV SDF_OpenDevice(SGD_HANDLE *phDeviceHandle);
SGD_RV SDF_HW_OpenDevice(SGD_HANDLE* phDeviceHandle,unsigned char* uiRandom,unsigned int uiRandomLen,unsigned char* pSignature,unsigned int pSignatureLen);

int SDF_HW_GenerateChallengeResponseCodes(unsigned char *pRandom, unsigned int *RDLen);
int SDF_HW_OpenDevice_Sign(unsigned char *uiRandom, unsigned int uiRandomLen, unsigned char *uiAuthPriKey, unsigned int uiAuthPriKeyLen, unsigned char *pSignature, unsigned int *pSignatureLen);
int SDF_HW_OpenDevice_Verify(void **phDeviceHandle, unsigned char *uiRandom, unsigned int uiRandomLen, unsigned char *pSignature, unsigned int pSignatureLen);

SGD_RV SDF_CloseDevice(SGD_HANDLE hDeviceHandle);
SGD_RV SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE* phSessionHandle);
SGD_RV SDF_CloseSession(SGD_HANDLE hSessionHandle);
SGD_RV SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO* pstDeviceInfo);

int SDF_HW_GetFirmwareVersion(void* hSessionHandle, unsigned char* uiSN, unsigned int* uiSNLen, unsigned char* sFirmware, unsigned int* ulFirmwareLen);
int SDF_HW_GetLibraryVersion(void* hSessionHandle, unsigned char* sLibraryVersion, unsigned int* ulLibraryVersionLen);
int SDF_HW_InitDevice(void *hSessionHandle,unsigned char *uiSN,unsigned int uiSNLen,unsigned char *uiPass,unsigned int uiPassLen);
//int SDF_HW_ModifyInitDevicePasswd(void *hSessionHandle,unsigned char *uiSN,unsigned int uiSNLen,unsigned char *uiPass,unsigned int uiPassLen,unsigned char *pCipherPass,unsigned int *pCPLen);

int SDF_HW_UpdateDevice(void* hSessionHandle, unsigned char* uiSN, unsigned int uiSNLen, unsigned char* FilePathName, unsigned int FPNLen);
int SDF_HW_ResetDevice(void* hSessionHandle, unsigned char* uiSN, unsigned int uiSNLen);
int SDF_HW_UKEY_AddUser(void* hSessionHandle, unsigned char* pucPublicKey, unsigned int PBKLen);
int SDF_HW_UKEYLogin_Verify(void* hSessionHandle, unsigned char* uiToken, unsigned int uiTKLen, unsigned char* uiSignNature, unsigned int uiSNLen);
int SDF_HW_LogoutUKey(void* hSessionHandle);
int SDF_HW_DecryptUKEYPin(void* hSessionHandle, unsigned char* uiCipherPin, unsigned int uiCPLen, unsigned char* pPin, unsigned int* pCPLen);

//SGD_RV SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR *pucRandom);

SGD_RV SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength);
SGD_RV SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex);
SGD_RV SDF_GetFirmwareVersion(SGD_HANDLE hSessionHandle, SGD_UCHAR * sFirmware, SGD_UINT32 * ulFirmwareLen);
SGD_RV SDF_GetLibraryVersion(SGD_HANDLE hSessionHandle, SGD_UCHAR * sLibraryVersion, SGD_UINT32 * ulLibraryVersionLen);

/*生命周期管理*/
int SDF_HW_CreateKey(void* hSessionHandle,KEKInfo* uiKEKInfo,unsigned char* uiSN,unsigned int uiSNLen,unsigned int VFNum,KEKNature* uiKEKNature,KEKCIPHER* pCipherKEK);
int SDF_HW_EnableKey(void* hSessionHandle, KEKInfo* uiKEKInfo);
int SDF_HW_DisableKey(void* hSessionHandle, KEKInfo* uiKEKInfo);
int SDF_HW_ScheduleKeyDeletion(void* hSessionHandle, KEKInfo* uiKEKInfo);
int SDF_HW_CancleKeyDeletion(void* hSessionHandle, KEKInfo* uiKEKInfo);
int SDF_HW_FinalKeyDeletion(void* hSessionHandle, KEKInfo* uiKEKInfo);
int SDF_HW_UpdateKeyAlias(void* hSessionHandle, KEKInfo* uiKEKInfo, unsigned char* uiAlias, unsigned int uiAliasLen);
int SDF_HW_UpdateKeyDescription(void* hSessionHandle, KEKInfo* uiKEKInfo, unsigned char* uiDescr, unsigned int uiDescrLen);
int SDF_HW_BackupKey(void* hSessionHandle, KEKInfo* uiKEKInfo, KEKCIPHER *pucKeyData);
int SDF_HW_RestoreKey(void* hSessionHandle, unsigned char* uiSN, unsigned int uiSNLen, unsigned int uiVFnum, KEKCIPHER *pucKeyData);
//?
//int SDF_HW_SyncKey(void* hSessionHandle, CallbackPullKEK* uiPullKEK);
//int SDF_HW_PostSyncKey(void *hSessionHandle, CallbackPostKEK *uiPostKEK);
int SDF_HW_GetKeyStatus(void* hSessionHandle, KEKInfo* uiKEKInfo, unsigned char* pKeyStatus, unsigned int* pKeyStatusLen, unsigned int* pKeyCount);
//?
//int SDF_HW_SetKeyStatus(void* hSessionHandle, KEKInfo* uiKEKInfo, KEKStaus* uiKeyStatus);

/*密钥句柄管理*/
int SDF_HW_ImportKey(void* hSessionHandle, unsigned char* uiKey, unsigned int uiKeyLen, void** phKeyHandle);
int SDF_DestroyKey(void* hSessionHandle, void* hKeyHandle);

/*传输通信*/
int SDF_HW_CreatePreMasterKey(void* hSessionHandle,	unsigned int uiAlgID,unsigned char* IV,unsigned int IVLen,unsigned char* uiPIN,unsigned int uiPINLen,KEKInfo* uiKEKInfo,unsigned int uiKeyType,	unsigned char* uiPublicKey,	unsigned int PBKLen,unsigned char* CMK_KEK,	unsigned int* CMK_KEKLen,unsigned char* CMK_Pub,unsigned int* CMK_PubLen,unsigned int ClientVer);
int SDF_HW_PreMasterKeyExchange(void * hSessionHandle, unsigned int uiKeyType, unsigned char *uiPrivateKey, unsigned int uiPIKLen, unsigned char *pucEncData, unsigned int pEDLen, unsigned char *pCipherKey, unsigned int *pCKLen);
int SDF_HW_PreMasterKeyExchange_SM2STD(void* hSessionHandle,unsigned int Flag,	unsigned char* OwnPublicKey,unsigned int OPBKLen,unsigned char* OwnPrivateKey,unsigned int OCPIKLen,unsigned char* OwnTmpPublicKey,unsigned int OTPBKLen,unsigned char* OwnTmpPrivateKey,unsigned int OTPIKLen,unsigned int uiKeyBits,
        unsigned char* pucSponsorID,unsigned int uiSponsorIDLength,unsigned char* pucResponseID,unsigned int uiResponseIDLength,unsigned char* pucResponsePublicKey,unsigned int RPBKLen,unsigned char* pucResponseTmpPublicKey,unsigned int RTPBKLen,unsigned char* pCipherKey,unsigned int* pCKLen);
int SDF_HW_PRF(void* hSessionHandle, unsigned int uiAlgID, KeyMaterials* uiKeyMaterials, KEYLEN* uiWorkKeyLen, unsigned char* pucKey,unsigned int* pucKeyLen);

/*非对称算法运算*/
int SDF_HW_AsymSign(void* hSessionHandle,unsigned int uiKeyType,unsigned char* uiPriKey,unsigned int uiPIKLen,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucSignature,unsigned int* pSNLen);
int SDF_HW_AsymVerify(void* hSessionHandle,unsigned int uiKeyType,unsigned char* uiPublicKey,unsigned int uiPBKLen,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucSignature,unsigned int pSNLen);
int SDF_HW_AsymEncrypt(void* hSessionHandle,unsigned int uiKeyType,unsigned char* uiPublicKey,unsigned int uiPBKLen,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucEncData,unsigned int* pEDLen);
int SDF_HW_AsymDecrypt(void* hSessionHandle,unsigned int uiKeyType,unsigned char* uiPriKey,unsigned int uiPIKLen,unsigned char* pucEncData,unsigned int pEDLen,unsigned char* pucData,unsigned int* puiDataLength);
int SDF_HW_AsymSign_SM9(void* hSessionHandle,unsigned char* pucSM9refSignUserPrivateKey,unsigned int UPIKLen,unsigned char* pucPairG,unsigned int uiPairGLen,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucSignature,unsigned int* pSignatureLen);
int SDF_HW_AsymVerify_SM9(void* hSessionHandle,unsigned char hid,unsigned char* uiUserID,unsigned int uiUserIDLen,unsigned char* uiSignMasterPublicKey,unsigned int uiPBKLen,unsigned char* uiPairG,unsigned int uiPairGLen,unsigned char* uiData,unsigned int uiDataLength,unsigned char* uiSignature,unsigned int uiSignatureLen);
int SDF_HW_AsymEncrypt_SM9(void* hSessionHandle,unsigned int uiEncMode,unsigned char hid,unsigned char* pucUserID,unsigned int uiUserIDLen,unsigned char* EncMasterPublicKey,unsigned int pPBKLen,unsigned char* uiPairG,unsigned int uiPairGLen,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucCipher,unsigned int* CipherLen);
int SDF_HW_AsymDecrypt_SM9(void* hSessionHandle,unsigned int uiEncMode,unsigned char* pucUserID,unsigned int uiUserIDLen,unsigned char* EncUserPrivateKey,unsigned int* UPIKLen,unsigned char* uiPairG,unsigned int uiPairGLen,unsigned char* pucCipher,unsigned int CipherLen,unsigned char* pucPlainData,unsigned int* puiPlainDataLength);
/*对称算法运算*/
int SDF_HW_SymmEncrypt(void* hSessionHandle,void* hKeyHandle1,void* hKeyHandle2,unsigned int uiAlgID,unsigned char* pucIV,unsigned int IVLen,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucEncData,unsigned int* puiEncDataLength,unsigned int uiDataUnitLength);
int SDF_HW_SymmDecrypt(void* hSessionHandle,void* hKeyHandle1,void* hKeyHandle2,unsigned int uiAlgID,unsigned char* pucIV,unsigned int IVLen,unsigned char* pucEncData,unsigned int  uiEncDataLength,unsigned char* pucData,unsigned int* puiDataLength,unsigned int uiDataUnitLength);
int SDF_HW_CalculateMAC(void* hSessionHandle,void* hKeyHandle,unsigned int uiAlgID,unsigned char* pucIV,unsigned int uiIVLength,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucMAC,unsigned int* puiMACLength);
int SDF_HW_SymmEncryptInit(void* hSessionHandle, void* hKeyHandle1, void* hKeyHandle2, unsigned int uiAlgID, unsigned char* pucIV, unsigned int uiIVLength, unsigned int uiPadFlag, unsigned int uiDataUnitLength, void* SYSCIPHER);
int SDF_HW_SymmEncryptUpdate(void* hSessionHandle,unsigned char* pucData,unsigned int puiDataLength,unsigned char* pucEncData,unsigned int* uiEncDataLength, void* SYSCIPHER);
int SDF_HW_SymmEncryptFinal(void* hSessionHandle,unsigned char* pucData,unsigned int puiDataLength,unsigned char* pucLastEncData,unsigned int* puiLastEncDataLength, void* SYSCIPHER);
int SDF_HW_SymmDecryptInit(void* hSessionHandle,void* hKeyHandle1,void* hKeyHandle2,unsigned int uiAlgID,unsigned char* pucIV,unsigned int uiIVLength,unsigned int uiPadFlag,unsigned int uiDataUnitLength, void* SYSCIPHER);
int SDF_HW_SymmDecryptUpdate(void* hSessionHandle,unsigned char* pucEncData,unsigned int uiEncDataLength,unsigned char* pucData,unsigned int* puiDataLength, void* SYSCIPHER);
int SDF_HW_SymmDecryptFinal(void* hSessionHandle,unsigned char* pucEncData,	unsigned int uiEncDataLength,unsigned char* pucLastData,unsigned int* puiLastDataLength, void* SYSCIPHER);
int SDF_HW_CalculateMACInit(void* hSessionHandle,void* hKeyHandle,unsigned int uiAlgID,unsigned char* pucIV,unsigned int uiIVLength,void* SYSCIPHER);
int SDF_HW_CalculateMACUpdate(void* hSessionHandle,unsigned char* pucData,unsigned int uiDataLength, void* SYSCIPHER);
int SDF_HW_CalculateMACFinal(void* hSessionHandle,unsigned char* pucMAC,unsigned int* puiMACLength, void* SYSCIPHER);
/*杂凑运算类函数*/
int SDF_HW_Hash(void* hSessionHandle,unsigned int uiAlgID,unsigned char* uiPublicKey,unsigned int uiPBKLen,unsigned char* pucID,unsigned int uiIDLength,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucHash,unsigned int* puiHashLength);
int SDF_HW_HashInit(void* hSessionHandle,unsigned int uiAlgID,unsigned char* uiPublicKey,unsigned int uiPBKLen,unsigned char* pucID,unsigned int uiIDLength, void* HASH_CONTEXT);
int SDF_HW_HashUpdate(void* hSessionHandle,unsigned char* pucData,unsigned int uiDataLength, void* HASH_CONTEXT);
int SDF_HW_HashFinal(void* hSessionHandle,unsigned char* pucHash,unsigned int* puiHashLength, void* HASH_CONTEXT);
int SDF_HW_CalculateHMAC(void* hSessionHandle,void* hKeyHandle,unsigned int uiAlgID,unsigned char* pucData,unsigned int uiDataLength,unsigned char* pucMAC,unsigned int* puiMACLength);
int SDF_HW_HmacInit(void* hSessionHandle,void* hKeyHandle,unsigned int uiAlgID, void* HMAC_CONTEXT);
int SDF_HW_HmacUpdate(	void *hSessionHandle,unsigned char *pucData,	unsigned int uiDataLength,	void* HMAC_CONTEXT);
int SDF_HW_HmacFinal(void* hSessionHandle,unsigned char* pucHmac,unsigned int* puiHmacLength, void* HMAC_CONTEXT);
int SDF_HW_PBKDF2(void* hSessionHandle,unsigned int uiAlgID,unsigned char* uiPass,unsigned int uiPasslen,unsigned char* uiSalt,unsigned int uiSaltlen,unsigned int uiCount,unsigned int keylen,unsigned char* pResult);
/*多包运算的上下文内存管理类函数*/
int SDF_HW_MemoryCalloc(void* hSessionHandle,unsigned int uiType,void** pHandle);
int SDF_HW_MemoryCopy(void* hSessionHandle,unsigned int uiType,void* uiSrcHandle,void* uiDstHandle);
int SDF_HW_MemoryFree(void* hSessionHandle,unsigned int uiType,void* uiHandle);
/*数据密钥管理*/
int SDF_GenerateRandom(void* hSessionHandle,unsigned int uiLength,unsigned char* pucRandom);
int SDF_HW_CreateDataKeyWithoutPlaintext(void *hSessionHandle, unsigned int uiAlgID, unsigned char *IV, unsigned int IVLen,unsigned char* uiPIN,unsigned int uiPINLen, KEKInfo *uiKEKInfo, unsigned int uiKeyLength, unsigned char *pCipherKey, unsigned int *pCKLen);
int SDF_HW_CreateDataKeyWithoutPlaintext_HMAC(void *hSessionHandle, unsigned int uiAlgID, unsigned char *IV, unsigned int IVLen,unsigned char* uiPIN,unsigned int uiPINLen, KEKInfo *uiKEKInfo, unsigned int uiKeyLength, unsigned char *pCipherKey, unsigned int *pCKLen);//开发过程中新加，后期需在文档中补充
int SDF_HW_CreateDataKeyPairsWithoutPlaintext(void *hSessionHandle,unsigned int uiAlgID,unsigned char *IV,unsigned int IVLen,unsigned char* uiPIN,unsigned int uiPINLen,KEKInfo *uiKEKInfo,unsigned int uiKeyType,unsigned char *pPublicKey,unsigned int * PBKLen,unsigned char *pCipherPriKey,unsigned int * PRKLen);
int SDF_HW_CreateMasterKeyPairs_SM9(void *hSessionHandle,unsigned int uiAlgID,unsigned char *IV,unsigned int IVLen,unsigned char* uiPIN,unsigned int uiPINLen,KEKInfo *uiKEKInfo,unsigned int uiKeyType,unsigned char *pucMasterPublicKey,unsigned int *pPBKLen,unsigned char *pucMasterPrivateKey,unsigned int *pPIKLen,unsigned char *pucPairG,unsigned int *puiPairGLen);
int SDF_HW_CreateUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyType, unsigned char *pucMasterPrivateKey, unsigned int pPIKLen, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned char *pucSM9refUserPrivateKey, unsigned int *pUPIKLen);
int SDF_HW_EncryptSecretkeyWithoutPlaintext(void *hSessionHandle,unsigned int uiAlgID,unsigned char *IV,unsigned int IVLen,unsigned char* uiPIN,unsigned int uiPINLen,KEKInfo *uiKEKInfo,unsigned int uiKeyType,unsigned char *uiPalinKey,unsigned int uiPKLen,unsigned char *pCipherKey,unsigned int *pCKLen);
int SDF_HW_CreateDEKPin(void* hSessionHandle,unsigned char* pPIN,unsigned int* pPINLen);
int SDF_HW_EnableDEKPin(void* hSessionHandle);
int SDF_HW_DisableDEKPin(void* hSessionHandle);
int SDF_HW_CalculatePubKey(void* hSessionHandle,unsigned char* uiPriKey,unsigned int uiPIKLen,unsigned char* pPubKey,unsigned int* pPBKLen);
/*导入密钥管理*/
int SDF_HW_GetParameterForImport(void *hSessionHandle,unsigned int uiAlgID,unsigned char *IV,unsigned int IVLen,KEKInfo *uiKEKInfo,unsigned char *pPublicKey,unsigned int *PBKLen,unsigned char *pCipherPriKey,unsigned int *PRKLen,unsigned char *pRandom,unsigned int uiRDLen);
int SDF_HW_ImportKeyMaterial(void* hSessionHandle, unsigned char* uiKeyMaterial, unsigned int uiKMLen, unsigned char* uiPriKey, unsigned int uiPIKLen, unsigned char* uiClusterPubKey, unsigned int uiCPBKLen, KEKCIPHER* pCKeyMaterial);
int SDF_HW_DeleteImportKeyMaterial(void* hSessionHandle, KEKInfo* uiKEKInfo);
/*授权管理*/
int SDF_HW_CreateGrant(void* hSessionHandle,KEKInfo* uiKEKInfounsigned ,char* uiProjectID,unsigned int uiPIDLen,unsigned char* uiDomainID,unsigned int uiDIDLen,unsigned char* uiRegionID,unsigned int uiRIDLen);
int SDF_HW_RevokeGrant(void* hSessionHandle,KEKInfo* uiKEKInfounsigned ,char* uiProjectID,unsigned int uiPIDLen,unsigned char* uiDomainID,unsigned int uiDIDLen,unsigned char* uiRegionID,unsigned int uiRIDLen);
int SDF_HW_RetireGrant(void* hSessionHandle,KEKInfo* uiKEKInfounsigned ,char* uiProjectID,unsigned int uiPIDLen,unsigned char* uiDomainID,unsigned int uiDIDLen,unsigned char* uiRegionID,unsigned int uiRIDLen);
/*轮转管理*/
int SDF_HW_EnableKeyRotation(void* hSessionHandle,KEKInfo* uiKEKInfo);
int SDF_HW_KeyRotation(void* hSessionHandle,KEKInfo* uiKEKInfo,unsigned char* KEKCipher,unsigned int* KCLen);
int SDF_HW_KeyRotationNotice(void* hSessionHandle,KEKInfo* uiKEKInfo);
int SDF_HW_DisableKeyRotation(void* hSessionHandle,KEKInfo* uiKEKInfo);
/*密钥同步（跨集群操作）*/
int SDF_HW_EnableKeySynch(void *hSessionHandle, KEKInfo *uiKEKInfo);
int SDF_HW_DisableKeySynch(void *hSessionHandle, KEKInfo *uiKEKInfo);
int SDF_HW_KeySynchStatus(void *hSessionHandle, KEKInfo *uiKEKInfo, unsigned int *SynchStatus);
int SDF_HW_ExportKeySynch(void *hSessionHandle, KEKInfo *uiKEKInfo, unsigned char *DevPubKey, unsigned int DevPubKeyLen, KEKCIPHER *KEKCipher);
int SDF_HW_ImportKeySynch(void *hSessionHandle, KEKCIPHER *KEKCipher);

/*标签管理*/

/*集群密钥管理*/
int SDF_HW_ReadClusterInfo(void *hSessionHandle, unsigned int uioffset, unsigned char *ClusterInfo, unsigned int CILen);
int SDF_HW_WriteClusterInfo(void *hSessionHandle, unsigned int uioffset, unsigned char *ClusterInfo, unsigned int CILen);
int SDF_HW_UpdateCdpRules(void *hSessionHandle, unsigned char *uiSN, unsigned int uiSNLen, unsigned int uiQOS, unsigned int uiQTI, unsigned int uiRTI, unsigned int uiATI, unsigned int uiARST);
int SDF_HW_UpdateResourceReport_Path(void *hSessionHandle, ReportAddrList *uiReportAddrList);
/*资源池信息*/
int SDF_HW_RescorceLock(void *hSessionHandle, unsigned char *uiSN, unsigned int uiSNLen, unsigned int uiTaskType, unsigned int uiLockFlag);
int SDF_HW_ResourceActive(void *hSessionHandle, unsigned char *uiSN, unsigned int uiSNLen, unsigned int uiMainFlag, unsigned int uiHealthFlag);
int SDF_HW_DownloadDevicesLog(void *hSessionHandle, unsigned char *uiSN, unsigned int uiSNLen, char *pLogFile, unsigned int pLFLen);
int SDF_HW_GetDevicePublickey(void *hSessionHandle, unsigned int uiFlag,unsigned char *uiSN, unsigned int uiSNLen, unsigned char* pucPublicKey, unsigned int* PBKLen);
/*集群密钥管理*/
int SDF_HW_CreateCdpKeyPair(void *hSessionHandle, unsigned char *uiSN, unsigned int uiSNLen,unsigned char* CdpID,unsigned int CIDLen);
int SDF_HW_ExportCdpKeyPair(void* hSessionHandle,unsigned char *CDPID,unsigned int CDPLen,unsigned char* DevPubKey,unsigned int DevPubKeyLen,unsigned char* C_ClusterKey,unsigned int* CKLen);
int SDF_HW_TransferCdpKeyPair(void *hSessionHandle,unsigned char *C_ClusterKey, unsigned int CKLen,unsigned int uiAlgID,unsigned char *IV,unsigned int IVLen,KEKInfo *uiKEKInfo,unsigned char *pC_ClusterKey,unsigned int *pCKLen);
int SDF_HW_TransferCpdKeyPairWithDevKey(void *hSessionHandle,KEKInfo *uiKEKInfo,unsigned int uiAlgID,unsigned char *IV,unsigned int IVLen,unsigned char *C_ClusterKey, unsigned int CKLen,unsigned char *DevPubKey, unsigned int DevPubKeyLen,unsigned char *pC_ClusterKey, unsigned int *pCKLen);
int SDF_HW_ImportCdpKeyPair (void * hSessionHandle, unsigned char *uiSN, unsigned int uiSNLen,unsigned char *CdpID, unsigned int CIDLen,unsigned char *CdpKeyPair,unsigned int CdpKeyPairLen);
/*告警管理*/
int SDF_HW_GetAlarms(void *hSessionHandle, unsigned char *uiSN, unsigned int uiSNLen, ALARMINFO *uiAlarms, unsigned int *total);
int SDF_HW_AlarmsOperation(void *hSessionHandle, unsigned char *uiAlarmID, unsigned int uiAIDLen, unsigned int uiOperMode, ALARMINFO *uiAlarms);
int SDF_HW_GetSpecAlarm(void *hSessionHandle, unsigned char *uiAlarmID, unsigned int uiAIDLen, ALARMINFO *uiAlarms);
/*VF公私钥管理*/
int SDF_HW_CreateVFKeyPair(void *hSessionHandle, unsigned char *pAuthKey, unsigned int *pAuthKeyLen);
int SDF_HW_ImportVFPublicKey(void * hSessionHandle, unsigned int uiKeyType, unsigned char *ProDevKey, unsigned int PDKLen, unsigned char *pSignature, unsigned int pSignatureLen);
int SDF_HW_UpdateVFKeyPair(void *hSessionHandle, unsigned char *pAuthPriKey, unsigned int pAuthPriKeyLen, unsigned char *pAuthKey, unsigned int *pAuthKeyLen, unsigned char *pSignature, unsigned int *pSignatureLen);
/*密码卡带内监测*/
int SDF_HW_MonitoringRunTime(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, unsigned long long *Ultime);
int SDF_HW_MonitoringPeckTime(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, unsigned int *pPKTime);
int SDF_HW_MonitoringLoad(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, float *pLoad);
int SDF_HW_MonitoringHealthStatus_VF(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, unsigned int *pHelStatus);
int SDF_HW_MonitoringPerformanceValue(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, float *pPValue);
int SDF_HW_MonitoringHealthStatus_PF(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, unsigned int *pHelStatus);
int SDF_HW_MonitoringVoltage(void *hSessionHandle, unsigned int VoltageType, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, float *pValtage);
int SDF_HW_MonitoringTemperature(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, float *pTemper);
int SDF_HW_MonitoringPower(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, float *pPower);
int SDF_HW_MonitoringKeyCapacity(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, unsigned int *pKeyCapacity, unsigned int *pUseCapacity);
int SDF_HW_MonitoringStorageChipLifespan(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, float *pLifespan);
int SDF_HW_MonitoringIssuerName(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, unsigned char *pIssuerName, unsigned int *pINUnitSize);
int SDF_HW_MonitoringDeviceName(void *hSessionHandle, unsigned char *pSN, unsigned int *pUnitSize, unsigned int *pNum, unsigned char *pDeviceName, unsigned int *pDNUnitSize);
int SDF_HW_MonitoringFaultLog(void *hSessionHandle, unsigned char *uiLogPath, unsigned int uiLPLen);
/*密码卡带外监测*/
int IIC_MonitoringVoltage(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, float *pValtage);
int IIC_MonitoringTemperature(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, float *pTemper);
int IIC_MonitoringPower(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, float *pPower);
int IIC_MonitoringKeyCapacity(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, unsigned int *pKeyCapacity, unsigned int *pUseCapacity);
int IIC_MonitoringStorageChipLifespan(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, float *pLifespan);
int IIC_MonitoringIssuerName(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, unsigned char *pIssuerName, unsigned int *pISLen);
int IIC_MonitoringDeviceName(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, unsigned char *pDeviceName, unsigned int *pDNLen);
int IIC_MonitoringFaultLog(unsigned char *uiDeviceAddr, unsigned int uiDALen, unsigned char *uiFieldAddr, unsigned int uiFALen, unsigned char *pLogData, unsigned int *pLDLen);
/*IPSec定制接口*/
int SDF_HW_SM2SignVerifyInit(void *hSessionHandle, unsigned int uiAlgID, unsigned char *uiPublicKey, unsigned int uiPBKLen, unsigned char *pucID, unsigned int uiIDLength, void* HASH_CONTEXT);
int SDF_HW_SM2SignVerifyUpdate(void *hSessionHandle, unsigned char *uiDek, unsigned int uiDekLen, unsigned char *uiData, unsigned int uiDataLen, void* HASH_CONTEXT);
int SDF_HW_SM2SignFinal(void *hSessionHandle, unsigned char *uiPriKey, unsigned int uiPIKLen, unsigned char *pSignature, unsigned int *pSignatureLen, void* HASH_CONTEXT);
int SDF_HW_SM2VerifyFinal(void *hSessionHandle, unsigned char *uiPubKey, unsigned int  uiPBKLen, unsigned char *pSignature, unsigned int pSignatureLen, void* HASH_CONTEXT);


int SDF_HW_HmacInitIPsec(void *hSessionHandle, unsigned int uiAlgID, unsigned char *uiHmacDek, unsigned int uiHmacDekLen, unsigned char *uiHmacKey, unsigned int uiHmacKeyLen, void* HMAC_CONTEXT);
int SDF_HW_HmacUpdateIPsec(void *hSessionHandle, unsigned char *uiDek, unsigned int uiDekLen, unsigned char *uiData, unsigned int uiDataLen, void* HMAC_CONTEXT);
int SDF_HW_HmacFinalIPsec(void *hSessionHandle, unsigned char *uiDek, unsigned int uiDekLen, unsigned char *pucHmac, unsigned int *puiHmacLength, void* HMAC_CONTEXT);
int SDF_HW_HashInitIPsec(void *hSessionHandle, unsigned int uiAlgID, unsigned char *uiPublicKey, unsigned int uiPBKLen, unsigned char *pucID, unsigned int uiIDLength,void* HASH_CONTEXT);
int SDF_HW_HashUpdateIPsec(void *hSessionHandle, unsigned char *uiDek, unsigned int uiDekLen, unsigned char *uiData, unsigned int uiDataLen, void* HASH_CONTEXT);
int SDF_HW_HashFinalIPsec(void *hSessionHandle, unsigned char *uiDek, unsigned int uiDekLen, unsigned char *pucHash, unsigned int *pucHashLength, void* HASH_CONTEXT);
#if 0
/*密钥管理类函数*/
SGD_RV SDF_GenerateKeyPair_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
SGD_RV SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
SGD_RV SDF_GenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDEInput, SGD_UINT32 uiDELength, \
										  SGD_UCHAR *pucDEOutput, SGD_UINT32  *puiDELength);

SGD_RV SDF_ImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle);
SGD_RV SDF_GetSymmKeyHandle(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);

SGD_RV SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,SGD_UINT32  uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
SGD_RV SDF_ExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, \
										ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, SGD_HANDLE *phAgreementHandle);
SGD_RV SDF_GenerateKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, \
							  ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, \
											  SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, \
											  ECCrefPublicKey  *pucResponsePublicKey, ECCrefPublicKey  *pucResponseTmpPublicKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithIPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithISK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, \
										  ECCCipher *pucEncDataOut);

/*非对称密码运算函数*/
SGD_RV SDF_ExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, \
										  SGD_UINT32 *puiOutputLength);
SGD_RV SDF_ExternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, \
										   SGD_UINT32 *puiOutputLength);


#ifndef GMT0018_2012
SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength);
#else
SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength);
SGD_RV SDF_InternalPublicKeyOperation_RSA_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength);
#endif
SGD_RV SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, ECCSignature *pucSignature);
SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
SGD_RV SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);
SGD_RV SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
SGD_RV SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);

/*对称密码运算函数*/
SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, \
				   SGD_UINT32 *puiEncDataLength);
SGD_RV SDF_Decrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData, \
				   SGD_UINT32 *puiDataLength);
SGD_RV SDF_CalculateMAC(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC, \
						SGD_UINT32 *puiMACLength);

/*杂凑运算函数*/
SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength);
SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength);
SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength);

/*用户文件操作函数*/
SGD_RV SDF_CreateFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiFileSize);
SGD_RV SDF_ReadFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 *puiReadLength, SGD_UCHAR *pucBuffer);
SGD_RV SDF_WriteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 uiWriteLength, SGD_UCHAR *pucBuffer);
SGD_RV SDF_DeleteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen);

int SDF_GenerateSignMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyBits, SM9refSignMasterPublicKey *pucPublicKey,
	SM9refSignMasterPrivateKey *pucPrivateKey, unsigned char *pucPairG, unsigned int *puiPairGLen);
int SDF_GenerateSignMasterPrivateKeyEx_SM9(void *hSessionHandle, unsigned int uiKeyBits, unsigned char *pucKS, SM9refSignMasterPublicKey *pucPublicKey,
	SM9refSignMasterPrivateKey *pucPrivateKey, unsigned char *pucPairG, unsigned int *puiPairGLen);
int SDF_GenerateEncMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyBits, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPrivateKey *pucPrivateKey,
	unsigned char *pucPairG,
	unsigned int *puiPairGLen);
int SDF_GenerateEncMasterPrivateKeyEx_SM9(void *hSessionHandle, unsigned int uiKeyBits, unsigned char *pucKE, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPrivateKey *pucPrivateKey,
	unsigned char *pucPairG,
	unsigned int *puiPairGLen);
int SDF_ExportSignMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignMasterPublicKey *pucPublicKey);
int SDF_ExportEncMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refEncMasterPublicKey *pucPublicKey);
int SDF_ExportSignMasterKeyPairG_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPairG, unsigned int *puiPairGLen);
int SDF_ExportEncMasterKeyPairG_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPairG, unsigned int *puiPairGLen);
int SDF_GenerateSignUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refSignUserPrivateKey *pucPrivateKey);
int SDF_GenerateSignUserPrivateKeyEx_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignMasterPrivateKey *pucSignMasterPrivateKey, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refSignUserPrivateKey *pucPrivateKey);
int SDF_GenerateEncUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refEncUserPrivateKey *pucPrivateKey);
int SDF_GenerateEncUserPrivateKeyEx_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refEncMasterPrivateKey *pucEncMasterPrivateKey, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refEncUserPrivateKey *pucPrivateKey);
int SWCSM_ImportUserSignPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignUserPrivateKey *pucPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen);
int SWCSM_ImportUserEncPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen);
int SDF_Sign_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignUserPrivateKey *pucPrivateKey,
	SM9refSignMasterPublicKey *pucMasterPublicKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_SignWithRandom_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignUserPrivateKey *pucPrivateKey,
	SM9refSignMasterPublicKey *pucMasterPublicKey, unsigned char *pucRandom, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_Verify_SM9(void * hSessionHandle, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refSignMasterPublicKey *pucMasterPublicKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_SignEx_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignUserPrivateKey *pucPrivateKey, SM9refSignMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_SignExWithRandom_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignUserPrivateKey *pucPrivateKey, SM9refSignMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucRandom, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_VerifyEx_SM9(void *hSessionHandle, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refSignMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_Encrypt_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pucCipher);
int SDF_EncryptWithRandom_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucRandom, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pucCipher);
int SDF_Decrypt_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucPrivateKey,
	SM9Cipher *pucCipher, unsigned char *pucPlainData, unsigned int *puiPlainDataLength);
int SDF_EncryptEx_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pucCipher);
int SDF_EncryptExWithRandom_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucRandom, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pucCipher);
int SDF_Encap_SM9(void *hSessionHandle, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned int uiKeyLen, unsigned char *pucKey, SM9refKeyPackage *pucKeyPackage);
int SDF_EncapExWithRandom_SM9(void *hSessionHandle, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned int uiKeyLen, unsigned char *pucRandom, unsigned char *pucKey, SM9refKeyPackage *pucKeyPackage);
int SDF_Decap_SM9(void *hSessionHandle, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucPrivateKey,
	SM9refKeyPackage *pucKeyPackage, unsigned int uiKeyLen, unsigned char *pucKey);
int SDF_GenerateAgreementDataWithSM9(void *hSessionHandle, unsigned char hid, unsigned char *pucResponseID, unsigned int uiResponseIDLength, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucTmpPublicKey, void **phAgreementHandle);
int SDF_GenerateAgreementDataWithSM9_Ex(void *hSessionHandle, unsigned char hid, unsigned char *pucResponseID, unsigned int uiResponseIDLength, SM9refEncMasterPublicKey *pucPublicKey,
	unsigned char *puc_rA, SM9refEncMasterPublicKey *pucTmpPublicKey, void **phAgreementHandle);
int SDF_GenerateAgreementDataAndKeyWithSM9(void *hSessionHandle, unsigned int uiKeyLen, unsigned char hid, unsigned char *pucResponseID, unsigned int uiResponseIDLen,
	unsigned char *pucSponsorID, unsigned int uiSponsorIDLen, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucResponsePrivateKey, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucSponsorTmpPublicKey, SM9refEncMasterPublicKey *pucResponseTmpPublicKey, unsigned char *pucHashSB, unsigned int *puiSBLen, unsigned char *pucHashS2,
	unsigned int *puiS2Len, void **phKeyHandle);
int SDF_GenerateAgreementDataAndKeyWithSM9_Ex(void *hSessionHandle, unsigned int uiKeyLen, unsigned char hid, unsigned char *pucResponseID, unsigned int uiResponseIDLen,
	unsigned char *pucSponsorID, unsigned int uiSponsorIDLen, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucResponsePrivateKey, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucSponsorTmpPublicKey, unsigned char *puc_rB, SM9refEncMasterPublicKey *pucResponseTmpPublicKey, unsigned char *pucHashSB, unsigned int *puiSBLen, unsigned char *pucHashS2,
	unsigned int *puiS2Len, unsigned char *pucSKB);
int SDF_GenerateKeyWithSM9(void *hSessionHandle, unsigned int uiKeyLen, unsigned char hid, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
	unsigned char *pucResponseID, unsigned int uiResponseIDLength, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucSponsorPrivateKey, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucResponseTmpPublicKey, unsigned char *pucHashSB, unsigned int uiSBLen, unsigned char *pucHashSA, unsigned int *puiSALen, void *hAgreementHandle,
	void **phKeyHandle);
int SDF_GenerateKeyWithSM9_Ex(void *hSessionHandle, unsigned int uiKeyLen, unsigned char hid, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
	unsigned char *pucResponseID, unsigned int uiResponseIDLength, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucSponsorPrivateKey, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucResponseTmpPublicKey, unsigned char *pucHashSB, unsigned int uiSBLen, unsigned char *pucHashSA, unsigned int *puiSALen, void *hAgreementHandle,
	unsigned char *pucSKA);
int SDF_GenerateKeyVerifySM9(void *hSessionHandle, unsigned char *pucHashS2, unsigned int uiS2Len, unsigned char *pucHashSA, unsigned int uiSALen);

int SWCSM_GenerateSignMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiKeyIndex);
int SWCSM_DeleteSignMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex);
int SWCSM_GenerateSignUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned int uiUserSignKeyIndex);
int SWCSM_DeleteSignUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiUserSignKeyIndex);
int SWCSM_GenerateEncMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiKeyIndex);
int SWCSM_DeleteEncMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex);
int SWCSM_GenerateEncUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	unsigned int uiUserEncKeyIndex);
int SWCSM_DeleteEncUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiUserEncKeyIndex);
int SWCSM_GetKeyStatus_SM9(void *hSessionHandle, unsigned int uiKeyType, unsigned int *puiKeyStatus, unsigned int *puiKeyCount);

//设备管理类
//int SDF_HW_InitDevice(void *hSessionHandle, unsigned int uiFlag);
//int SDF_HW_UpdateDevice(void *hSessionHandle, unsigned char *FilePathName);
//int SDF_HW_ResetDevice(void *hSessionHandle);
int SDF_HW_ImportProDevKey(void * hSessionHandle, unsigned int uiKeyIndex, unsigned char *ProDevKey, unsigned int PDKLen);

//密钥管理类
int SDF_HW_CreateKEK(void *hSessionHandle, unsigned char *uiKEKID, unsigned int uiKEKIDLen,unsigned char *Nature,unsigned int NELen);
int SDF_HW_DeleteKEK(void *hSessionHandle, unsigned char *uiKEKID, unsigned int uiKEKIDLen);
int SDF_HW_GetKeyStatus(void *hSessionHandle,unsigned char *pKeyStatus[],unsigned int *pKeyCount);
int SDF_HW_GenSymmKey(void *hSessionHandle, unsigned int AlgID, unsigned char *uiKEKID, unsigned int uiKEKIDLen, unsigned int uiKeyLength, SysCKey *pCipherKey);
int SDF_HW_GenerateECCKeyPair(void *hSessionHandle, unsigned int AlgID,unsigned char *uiKEKID, unsigned int uiKEKIDLen, ECCrefPublicKey *pPublicKey, C_SM2Pairs *pCipherPriKey);
int SDF_HW_ExportPublicKey_ECC(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey* pucPublicKey);

//SM2密钥协商
int SDF_HW_GenerateKeyWithECC_Ext(void *hSessionHandle, unsigned int Flag, ECCrefPublicKey *OwnPublicKey, SysCKey *uiCipherPriKey, ECCrefPublicKey *OwnTmpPublicKey, SysCKey *OwnTmpPrivateKey,\
	unsigned int uiKeyBits, unsigned char* pucSponsorID, unsigned int uiSponsorIDLength, unsigned char* pucResponseID, unsigned int uiResponseIDLength, \
	ECCrefPublicKey* pucResponsePublicKey, ECCrefPublicKey* pucResponseTmpPublicKey, SysCKey* pucKey);

int SDF_HW_ImportKey(void *hSessionHandle, SGD_UCHAR *pucKey, void **phKeyHandle);

//非对称算法运算类函数
int SDF_HW_Sign_ECC(void *hSessionHandle, SysCKey *uiCipherPriKey, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
int SDF_HW_Verify_ECC(void *hSessionHandle, ECCrefPublicKey *uiPublicKey, unsigned char *pucData, unsigned int  uiDataLength, ECCSignature *pucSignature);
int SDF_HW_Encrypt_ECC(void *hSessionHandle, ECCrefPublicKey *uiPublicKey, unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData);
int SDF_HW_Decrypt_ECC(void *hSessionHandle, SysCKey *uiCipherPriKey, ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength);
int SDF_HW_ExternalDecrypt_ECCWithKEK(void * hSessionHandle, SysCKey *pucPrivateKey, ECCCipher *pucEncData, SysCKey *pucData);
/*
//对称算法运算类函数
int SDF_HW_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int IVLen, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int  *puiEncDataLength);
int SDF_HW_Encrypt_Ex(void *hSessionHandle, void *hKeyHandle1, void *hKeyHandle2, unsigned int uiAlgID, unsigned char *pucIV, unsigned int IVLen, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength, unsigned int uiDataUnitLength);
int SDF_HW_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int IVLen, unsigned char *pucEncData, unsigned int  uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
int SDF_HW_Decrypt_Ex(void *hSessionHandle, void *hKeyHandle1, void *hKeyHandle2, unsigned int uiAlgID, unsigned char *pucIV, unsigned int IVLen, unsigned char *pucEncData, unsigned int  uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength, unsigned int uiDataUnitLength);

int SDF_HW_EncryptInit_Ex(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength, unsigned int uiPadFlag,SYSCIPHER_HANDLE *SYSCIPHER);
int SDF_HW_EncryptUpdate_Ex(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength, SYSCIPHER_HANDLE SYSCIPHER);
int SDF_HW_EncryptFinal_Ex(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength, SYSCIPHER_HANDLE SYSCIPHER);

int SDF_HW_DecryptInit_Ex(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength, unsigned int uiPadFlag,SYSCIPHER_HANDLE *SYSCIPHER);
int SDF_HW_DecryptUpdate_Ex(void *hSessionHandle, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength, SYSCIPHER_HANDLE SYSCIPHER);
int SDF_HW_DecryptFinal_Ex(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puiLastDataLength, SYSCIPHER_HANDLE SYSCIPHER);

int SDF_HW_CalculateMAC(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucMAC, unsigned int  *puiMACLength);
int SDF_HW_CalculateMACInit_Ex(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength, SYSCIPHER_HANDLE *SYSCIPHER);
int SDF_HW_CalculateMACUpdate_Ex(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, SYSCIPHER_HANDLE SYSCIPHER);
int SDF_HW_CalculateMACFinal_Ex(void *hSessionHandle, unsigned char *pucMAC, unsigned int *puiMACLength, SYSCIPHER_HANDLE SYSCIPHER);

//杂凑运算类函数
int SDF_HW_HashInit_Ex(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucID, unsigned int uiIDLength, HASH_HANDLE_Ex *HASH_CONTEXT);
int SDF_HW_HashUpdate_Ex(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, HASH_HANDLE_Ex HASH_CONTEXT);
int SDF_HW_HashFinal_Ex(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength, HASH_HANDLE_Ex HASH_CONTEXT);

//HMAC
int SDF_HW_HmacInit(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, HMAC_HANDLE* HMAC_CONTEXT);
int SDF_HW_HmacUpdate(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, HMAC_HANDLE HMAC_CONTEXT);
int SDF_HW_HmacFinal(void *hSessionHandle, unsigned char *pucHmac, unsigned int *puiHmacLength, HMAC_HANDLE HMAC_CONTEXT);
*/
//备份恢复类函数
int SDF_HW_Backup (void *hSessionHandle, ECCrefPublicKey * pPubkey, ECCSignature *Sign,unsigned char *passwd, unsigned int uiPwdLength,unsigned char *pucKEKID, unsigned int uiKEKIDLen, unsigned char *pucKeyData, unsigned int *puiKeyDataLength);
int SDF_HW_Restore(void *hSessionHandle, unsigned char *pucKeyData, unsigned int uiKeyDataLength);

//监控类函数
int SDF_HW_MonitoringData(void *hSessionHandle, unsigned int inSel, unsigned char *output, unsigned int *outlen);
int SDF_HW_ReadClusterInfo(void *hSessionHandle, unsigned int uiOffset,unsigned char *ClusterInfo, unsigned int *CILen);
int SDF_HW_WriteClusterInfo(void *hSessionHandle, unsigned int uiOffset,unsigned char *ClusterInfo, unsigned int CILen);

int SDF_HW_PRF(void *hSessionHandle, unsigned int uiAlgID, KeyMaterials *uiKeyMaterials, KEYLEN* uiWorkKeyLen, unsigned char *pucKey, unsigned int *pucKeyLen);
#endif
#ifdef __cplusplus
}
#endif

#endif /*#ifndef _SW_SDS_H_*/
