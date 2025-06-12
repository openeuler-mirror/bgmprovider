#ifndef CRYPTOCARDSDK_CRYPTO_SDK_PF_H
#define CRYPTOCARDSDK_CRYPTO_SDK_PF_H
#include "crypto_sdk_vf.h"
#include "crypto_sdk_struct.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifndef VF_SDK
//【KEK生命周期管理开始】
/**
 * @brief 创建KEK
 * @param kekInfo               【IN】【非空】kek标识信息
 * @param sn                    【IN】[是]卡设备序列号
 * @param snLen                 【IN】[是]卡设备序列号长度
 * @param nature                【IN】【非空】kek的属性信息
 * @param cipherKek             【OUT】【非空】kek（集群密钥加密）
 * @param cipherKekLen          【IN/OUT】kek密文长度
 * @return 错误码
 */
int CDM_CreateKey(const KEKInfo* kekInfo, const unsigned char* sn, unsigned int snLen, const KEKNature* nature,
                  void* cipherKek, unsigned int* cipherKekLen);
/**
 * @brief 启用密钥KEK
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_EnableKey(const KEKInfo* kekInfo);

/**
 * @brief 禁用密钥KEK
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_DisableKey(const KEKInfo* kekInfo);

/**
 * @brief 计划删除kek
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_ScheduleKeyDeletion(const KEKInfo* kekInfo);

/**
 * @brief 取消计划删除
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_CancelKeyDeletion(const KEKInfo* kekInfo);

/**
 * @brief 到期正式删除
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_FinalKeyDeletion(const KEKInfo* kekInfo);

/**
 * @brief 修改别名
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param alias                     【IN】别名
 * @param aliasLen                  【IN】别名长度
 * @return 错误码
 */
int CDM_UpdateKeyAlias(const unsigned char* sn, unsigned int snLen, const KEKInfo* kekInfo, const char* alias,
                       unsigned int aliasLen);

/**
 * @brief 修改描述
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param description               【IN】描述信息
 * @return 错误码
 */
int CDM_UpdateKeyDescription(const unsigned char* sn, unsigned int snLen, const KEKInfo* kekInfo,
                             const char* description);
//【KEK生命周期管理结束】

//【KEK密钥材料导入导出、轮换、授权开始】
/**
 * @brief 导入密钥材料
 * @param keyCipher                【IN】由CDMS临时加密的密文KEK
 * @param kcLen                    【IN】密钥材料KEK的长度
 * @param kekInfo                  【IN】KEKInfo
 * @param priKey                   【IN】加密KEK的私钥
 * @param priKeyKen                【IN】私钥长度
 * @param clusterPubKey            【IN】集群公钥
 * @param cpkLen                   【IN】集群公钥长度
 * @param keyData                  【OUT】由集群密钥加密的KEK
 * @return 错误码
 */
int CDM_ImportKeyMaterial(const unsigned char* keyCipher, unsigned int kcLen, const KEKInfo* kekInfo,
                          const unsigned char* priKey, unsigned int priKeyLen, const unsigned char* clusterPubKey,
                          unsigned int cpkLen, void* keyData, unsigned int* keyDataLen);

/**
 * @brief 删除导入的密钥材料
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_DeleteImportedKeyMaterial(const KEKInfo* kekInfo);

/**
 * @brief 创建授权
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param projectId                 【IN】
 * @param projectIdLen              【IN】
 * @param domainId                  【IN】账号ID
 * @param domainIdLen               【IN】账号ID长度
 * @param regionId                  【IN】
 * @param regionIdLen               【IN】
 * @param cdpId                     【IN】cdp ID
 * @param cdpIdLen                  【IN】cdp ID长度
 * @return 错误码
 */
int CDM_CreateGrant(const KEKInfo* kekInfo, const unsigned char* projectId, unsigned int projectIdLen,
                    const unsigned char* domainId, unsigned int domainIdLen, const unsigned char* regionId,
                    unsigned int regionIdLen, const unsigned char* cdpId, unsigned int cdpIdLen);

/**
 * @brief 撤销授权
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param projectId                 【IN】
 * @param projectIdLen              【IN】
 * @param domainId                  【IN】
 * @param domainIdLen               【IN】
 * @param regionId                  【IN】
 * @param regionIdLen               【IN】
 * @param cdpId                     【IN】
 * @param cdpIdLen                  【IN】
 * @return 错误码
 */
int CDM_RevokeGrant(const KEKInfo* kekInfo, const unsigned char* projectId, unsigned int projectIdLen,
                    const unsigned char* domainId, unsigned int domainIdLen, const unsigned char* regionId,
                    unsigned int regionIdLen, const unsigned char* cdpId, unsigned int cdpIdLen);

/**
 * @brief 开启轮换
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_EnableKeyRotation(const KEKInfo* kekInfo);

/**
 * @brief 指定设备轮换更新
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param cipherKek                 【OUT】集群密钥加密的更新后的KEK
 * @return 错误码
 */
int CDM_KeyRotation(const unsigned char* sn, unsigned int snLen, const KEKInfo* kekInfo, void* cipherKek,
                    unsigned int* cipherKekLen);

/**
 * @brief 广播更新KEK指令,卡内有kekID,触发拉取CDMS更新
 * @param kekInfo                  【IN】KEKInfo
 * @param regionId                 【IN】
 * @param regionIdLen              【IN】
 * @param cdpId                    【IN】
 * @param cdpIdLen                 【IN】
 * @return 错误码
 */
int CDM_KeyRotationNotice(const KEKInfo* kekInfo, const unsigned char* regionId, unsigned int regionIdLen,
                          const unsigned char* cdpId, unsigned int cdpIdLen);

/**
 * @brief 关闭密钥轮换
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_DisableKeyRotation(const KEKInfo* kekInfo);

/**
 * @brief 查询密钥轮换状态
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param status                    【OUT】查询结果
 * @return 错误码
 */
int CDM_GetKeyRotationStatus(const KEKInfo* kekInfo, unsigned int* status);
//【KEK密钥材料导入导出、轮换、授权结束】

//【密钥同步、标签管理开始】
int CDM_EnableKeySynch(const KEKInfo* kekInfo, const unsigned char* regionId, unsigned int regionIdLen,
                       const unsigned char* cdpId, unsigned int cdpIdLen);
int CDM_UpdateKeySynch(const KEKInfo* kekInfo, const unsigned char* regionId, unsigned int regionIdLen,
                       const unsigned char* cdpId, unsigned int cdpIdLen);
int CDM_DisableKeySynch(const KEKInfo* kekInfo);
/**
 * @param status            【OUT】 0-未开启、1-已开启
 */
int CDM_GetKeySynchStatus(const KEKInfo* kekInfo, unsigned int* status);

int CDM_ConfigKeyNatureSize(KEKInfo* kekInfo, unsigned int flag, unsigned int projectIdNum, unsigned int domainIdNum,
                            unsigned int cdpIdNum, unsigned int regionIdNum);
//【密钥同步、标签管理结束】

//【集群密钥开始】
/**
 * @brief 创建指定集群的公私密钥对
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param cdpId                     【IN】集群ID
 * @param cdpIdLen                  【IN】集群ID长度
 * @param pubKey                    【IN】输出的集群公钥
 * @param pubKeyLen                 【IN/OUT】输出的集群公钥空间大小
 * @return 错误码
 */
int CDM_CreateCDPKeyPair(const unsigned char* sn, unsigned int snLen, const unsigned char* cdpId, unsigned int cdpIdLen,
                         char* pubKey, unsigned int* pubKeyLen);

/**
 * @brief 导出集群密钥对
 * @param cdpId                     【IN】集群ID
 * @param cdpIdLen                  【IN】集群ID长度
 * @param devPubKey                 【IN】目标设备公钥
 * @param devPubKeyLen              【IN】目标设备公钥长度
 * @param clusterKey                【IN】输出的集群密钥对
 * @param clusterKeyLen             【IN/OUT】输出的集群密钥对长度
 * @return 错误码
 */
int CDM_ExportCDPKeyPair(const unsigned char* cdpId, unsigned int cdpIdLen, const char* devPubKey,
                         unsigned int devPubKeyLen, char* clusterKey, unsigned int* clusterKeyLen);

/**
 * @brief 管理集群使用其KEK对密文集群密钥对（有sn对应的设备公钥加密）转加密
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param clusterKey                【IN】输出的集群密钥对
 * @param clusterKeyLen             【IN】输出的集群密钥对长度
 * @param algID                     【IN】KEK转加密的加密算法
 * @param iv                        【IN】初始化向量
 * @param ivLen                     【IN】初始化向量长度
 * @param kekInfo                   【IN】KEK信息
 * @param cipherClusterKey          【OUT】转换的集群密钥对
 * @param cipherClusterKeyLen       【IN/OUT】转换的集群密钥对长度
 * @return 错误码
 */
int CDM_TransferCDPKeyPair(const char* clusterKey, unsigned int clusterKeyLen, unsigned int algID,
                           const unsigned char* iv, unsigned int ivLen, KEKInfo* kekInfo, char* cipherClusterKey,
                           unsigned int* cipherClusterKeyLen);

/**
 * @brief 使用业务集群某节点的设备公钥A（由节点导出的设备公钥）、
 * 和管理集群KEK加密的业务集群密钥（先 CDM_ExportCDPKeyPair使用管理集群设备公钥导出业务集群密钥、再CDM_TransferCDPKeyPair使用管理集群KEK转加密）
 * 将由管理集群KEK加密保护的业务集群密钥、转化为业务集群设备公钥A加密输出
 * @param kekInfo                   【IN】KEK信息
 * @param algID                     【IN】KEK转加密的加密算法
 * @param iv                        【IN】初始化向量
 * @param ivLen                     【IN】初始化向量长度
 * @param clusterKey                【IN】由管理集群的KEK加密保护的业务集群密钥对
 * @param clusterKeyLen             【IN】clusterKey的长度
 * @param devPubKey                 【IN】业务集群的某节点设备公钥
 * @param devPubKeyLen              【IN】设备公钥长度
 * @param cipherClusterKey          【OUT】转换加密后的集群密钥对
 * @param cipherClusterKeyLen       【IN/OUT】转换加密后的集群密钥对长度
 * @return 错误码
 */
int CDM_TransferCDPKeyPairWithDevKey(KEKInfo* kekInfo, unsigned int algId, const unsigned char* iv, unsigned int ivLen,
                                     const char* clusterKey, unsigned int clusterKeyLen, const char* devPubKey,
                                     unsigned int devPubKeyLen, char* cipherClusterKey,
                                     unsigned int* cipherClusterKeyLen);

/**
 * @brief 导入集群密钥对
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param cdpId                     【IN】集群ID
 * @param cdpIdLen                  【IN】集群ID长度
 * @param key                       【IN】密文集群密钥对
 * @param keyLen                    【IN】密文集群密钥对长度
 * @return 错误码
 */
int CDM_ImportCDPKeyPair(const unsigned char* sn, unsigned int snLen, const unsigned char* cdpId, unsigned int cdpIdLen,
                         const char* key, unsigned int keyLen);
//【集群密钥结束】

//【集群管理开始】

/**
 * @brief 写入的集群归属信息到密码卡
 * @param clusterInfo               【IN】写入的信息
 * @param infoLen                   【IN】要写入的信息长度
 * @return 错误码
 */
int CDM_WriteClusterInfo(unsigned char* clusterInfo, unsigned int infoLen);

/**
 * @brief 从密码卡中删除写入的集群归属信息
 * @return 错误码
 */
int CDM_DeleteClusterInfo(void);

/**
 * @brief 从密码卡中读取写入的集群归属信息
 * @param clusterInfo               【OUT】读取的信息
 * @param infoLen                   【IN】要读取的信息长度
 * @return 错误码
 */
int CDM_GetClusterInfo(unsigned char* clusterInfo, unsigned int infoLen);

/**
 * @brief 从指定集群导出KEK
 * @param sn                        【IN】设备序列号
 * @param snLen                     【IN】设备序列号长度
 * @param kekInfo                   【IN】kek信息
 * @param targetPubKey              【IN】目标端公钥
 * @param targetPubKeyLen           【IN】目标端公钥长度
 * @param cipher                    【OUT】KEK密文
 * @param cipherLen                 【IN/OUT】KEK密文长度
 * @return
 */
int CDM_ExportKeySynch(unsigned char* sn, unsigned int snLen, KEKInfo* kekInfo, char* targetPubKey,
                       unsigned int targetPubKeyLen, void* cipher, unsigned int* cipherLen);

/**
 * @brief 查询密码卡设备所有状态信息
 * @param devNum                    【OUT】当前物理卡个数
 * @param vDevNum                   【OUT】当前的VF设备个数
 * @param resInfoList               【OUT】物理密码卡状态信息列表
 * @param resInfoListLen            【IN/OUT】物理密码卡状态信息列表长度
 * @param vResInfoList              【OUT】虚拟密码卡状态信息列表
 * @param vResInfoListLen           【IN/OUT】虚拟密码卡状态信息列表长度
 * @return 错误码
 */
int CDM_GetDeviceAllStatus(unsigned int* devNum, unsigned int* vDevNum, void* resInfoList, unsigned int* resInfoListLen,
                           void* vResInfoList, unsigned int* vResInfoListLen);

// 获取resInfoList里的成员
int CDM_GetPhysicalDeviceVoltage(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                 float* voltageType_1_2, float* voltageType_3_3, float* voltageType_12,
                                 float* voltageTypeBattery);

int CDM_GetPhysicalDeviceTemperature(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                     float* temper);

int CDM_GetPhysicalDevicePower(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex, float* power);

int CDM_GetPhysicalDeviceLifespan(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                  float* lifespan);

int CDM_GetPhysicalDeviceHealth(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                unsigned int* healthStatus);

int CDM_GetPhysicalDeviceFirmware(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                  unsigned char* firmware, unsigned int* firmwareLen);

int CDM_GetPhysicalDeviceLibVersion(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                    unsigned char* libraryVersion, unsigned int* libraryVersionLen);

int CDM_GetPhysicalDeviceDeviceInfo(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                    DeviceBaseInfo* deviceInfo);
//【集群管理结束】

//【密钥备份恢复开始】
int CDM_BackupKEK(const unsigned char* sn, unsigned int snLen, const KEKInfo* kekInfo, void* cipherKek,
                  unsigned int* cipherKekLen);

int CDM_RestoreKEK(const unsigned char* sn, unsigned int snLen, const void* keyData, unsigned int keyDataLen);
//【密钥备份恢复结束】

//【虚拟设备VF密钥信息开始】
/**
 * @brief 添加VF公钥或KEK信息到密码卡
 * @param uuid                      【IN】VF的UUID
 * @param uuidLen                   【IN】VF的UUID长度
 * @param devType                   【IN】VF的设备类型
 * @param devTypeLen                【IN】VF的设备类型长度
 * @param keyType                   【IN】待添加的密钥类型
 * @param key                       【IN】待添加的密钥
 * @param keyLen                    【IN】待添加的密钥长度
 * @param failedKey                 【OUT】失败的密钥
 * @param failedKeyLen              【OUT】失败的密钥长度
 * @return 错误码
 */
int CDM_AddVFKeyInfo(const unsigned char* uuid, unsigned int uuidLen, const char* devType, unsigned int devTypeLen,
                     unsigned int keyType, const unsigned char* key, unsigned int keyLen, unsigned char* failedKey,
                     unsigned int* failedKeyLen);
/**
 * 拼接鉴权公钥转结构体数组
 * @param uuid                      【IN】虚拟机id
 * @param uuidLen                   【IN】虚拟机id长度
 * @param keyInfo                   【IN】鉴权密钥信息
 * @param keyInfoLen                【IN】鉴权密钥信息长度
 * @param keyList                   【OUT】密钥结构体数组
 * @param keyCount                  【IN/OUT】数组的个数
 * @return 错误码
 */
int CDM_GetVFAuthKeyStruct(const unsigned char* uuid, unsigned int uuidLen, const unsigned char* keyInfo,
                           unsigned int keyInfoLen, AuthKeyHandle keyList, unsigned int* keyCount);

/**
 * 结构体数据转拼接鉴权公钥
 * @param keyList                   【IN】密钥结构体数据
 * @param keyCount                  【IN】数据的个数
 * @param keyInfo                   【OUT】鉴权密钥
 * @param keyInfoLen                【IN/OUT】鉴权密钥长度
 * @return 错误码
 */
int CDM_SetVFAuthKeyStruct(AuthKeyHandle keyList, unsigned int keyCount, unsigned char* keyInfo,
                           unsigned int* keyInfoLen);

/**
 * @brief 删除VF公钥或KEK信息到密码卡
 * @param uuid                      【IN】VF的UUID
 * @param uuidLen                   【IN】VF的UUID长度
 * @param keyType                   【IN】待删除的密钥类型
 * @param key                       【IN】待删除的密钥
 * @param keyLen                    【IN】待删除的密钥长度
 * @param failedKey                 【OUT】失败的密钥
 * @param failedKeyLen              【OUT】失败的密钥长度
 * @return 错误码
 */
int CDM_DeleteVFKeyInfo(const unsigned char* uuid, unsigned int uuidLen, unsigned int keyType, const unsigned char* key,
                        unsigned int keyLen, unsigned char* failedKey, unsigned int* failedKeyLen);

/**
 * @brief 从密码卡获取VF密钥信息
 * @param uuid                      【IN】VF的UUID
 * @param uuidLen                   【IN】VF的UUID长度
 * @param keyType                   【IN】待删除的密钥类型
 * @param keyCount                  【OUT】输出的总密钥信息数量
 * @param keyInfo                   【IN】输出的密钥信息
 * @param keyInfoLen                【IN】输出的密钥信息长度
 * @return 错误码
 */
int CDM_GetVFKeyInfo(const unsigned char* uuid, unsigned int uuidLen, unsigned int keyType, unsigned int* keyCount,
                     unsigned char* keyInfo, unsigned int* keyInfoLen);

/**
 * @brief 删除VF中所有密钥信息
 * @param uuid                      【IN】VF的UUID
 * @param uuidLen                   【IN】VF的UUID长度
 * @return 错误码
 */
int CDM_EraseVFKeyInfo(unsigned char* uuid, unsigned int uuidLen);
//【虚拟设备VF密钥信息结束】

//【Agent交互开始】
int CDM_ReadCardTasks(int timeout, CardTaskCallback callback);

//【Agent交互结束】

//【设备监控开始】
/**
 * @brief 初始化设备
 * @param sn                        【IN】设备序列号
 * @param snLen                     【IN】设备序列号长度
 * @param pass                      【IN】明文/密文口令
 * @param passLen                   【IN】口令长度
 * @return 错误码
 */
int CDM_InitDevice(const unsigned char* pass, unsigned int passLen);

/**
 * @brief 升级固件
 * @param filePath                  【IN】固件升级文件路径
 * @param filePathLen               【IN】固件升级文件路径长度
 * @return 错误码
 */
int CDM_UpdateDevice(const char* filePath, unsigned int filePathLen);

/**
 * @brief 升级固件后复位设备
 * @return 错误码
 */
int CDM_ResetDevice(void);
//【设备监控结束】

//【CryptoSetup专属开始】
/**
 * @brief 导入密钥
 * @param key                       【IN】【是】密文密钥DEK
 * @param keyLen                    【IN】【是】密文密钥长度
 * @param pin                       【IN】保护DEK的DekPin编码结果
 * @param pinLen                    【IN】DekPin编码结果长度
 * @param keyBytes                  【OUT】【是】DEK密钥句柄
 * @param keyBytesLen               【OUT】【是】DEK密钥句柄长度
 * @return 错误码
 */
int CDM_ImportKeyHandleCrypto(char* key, unsigned int keyLen, char* pin, unsigned int pinLen, unsigned char* keyBytes,
                              unsigned int* keyBytesLen);
//【CryptoSetup专属结束】

#endif
#ifdef __cplusplus
}
#endif
#endif  //CRYPTOCARDSDK_CRYPTO_SDK_PF_H
