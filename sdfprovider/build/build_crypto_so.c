#include <stdio.h>

#include "crypto_sdk_vf.h"
#include "crypto_sdk_pf.h"

int CDM_CreateKey(const KEKInfo* kekInfo, const unsigned char* sn, unsigned int snLen, const KEKNature* nature,
                  void* cipherKek, unsigned int* cipherKekLen) {
    return 0;
}
/**
 * @brief 启用密钥KEK
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_EnableKey(const KEKInfo* kekInfo) {
    return 0;
}

/**
 * @brief 禁用密钥KEK
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_DisableKey(const KEKInfo* kekInfo) {
    return 0;
}

/**
 * @brief 计划删除kek
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_ScheduleKeyDeletion(const KEKInfo* kekInfo) {
    return 0;
}

/**
 * @brief 取消计划删除
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_CancelKeyDeletion(const KEKInfo* kekInfo) {
    return 0;
}

/**
 * @brief 到期正式删除
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_FinalKeyDeletion(const KEKInfo* kekInfo) {
    return 0;
}

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
                       unsigned int aliasLen) {
    return 0;
}

/**
 * @brief 修改描述
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param description               【IN】描述信息
 * @return 错误码
 */
int CDM_UpdateKeyDescription(const unsigned char* sn, unsigned int snLen, const KEKInfo* kekInfo,
                             const char* description) {
    return 0;
}
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
                          unsigned int cpkLen, void* keyData, unsigned int* keyDataLen) {
    return 0;
}

/**
 * @brief 删除导入的密钥材料
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_DeleteImportedKeyMaterial(const KEKInfo* kekInfo) {
    return 0;
}

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
                    unsigned int regionIdLen, const unsigned char* cdpId, unsigned int cdpIdLen) {
    return 0;
}

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
                    unsigned int regionIdLen, const unsigned char* cdpId, unsigned int cdpIdLen) {
    return 0;
}

/**
 * @brief 开启轮换
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_EnableKeyRotation(const KEKInfo* kekInfo) {
    return 0;
}

/**
 * @brief 指定设备轮换更新
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param cipherKek                 【OUT】集群密钥加密的更新后的KEK
 * @return 错误码
 */
int CDM_KeyRotation(const unsigned char* sn, unsigned int snLen, const KEKInfo* kekInfo, void* cipherKek,
                    unsigned int* cipherKekLen) {
    return 0;
}

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
                          const unsigned char* cdpId, unsigned int cdpIdLen) {
    return 0;
}

/**
 * @brief 关闭密钥轮换
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @return 错误码
 */
int CDM_DisableKeyRotation(const KEKInfo* kekInfo) {
    return 0;
}

/**
 * @brief 查询密钥轮换状态
 * @param sn                        【IN】sn号
 * @param snLen                     【IN】sn长度
 * @param kekInfo                   【IN】KEKInfo
 * @param status                    【OUT】查询结果
 * @return 错误码
 */
int CDM_GetKeyRotationStatus(const KEKInfo* kekInfo, unsigned int* status) {
    return 0;
}
//【KEK密钥材料导入导出、轮换、授权结束】

//【密钥同步、标签管理开始】
int CDM_EnableKeySynch(const KEKInfo* kekInfo, const unsigned char* regionId, unsigned int regionIdLen,
                       const unsigned char* cdpId, unsigned int cdpIdLen) {
    return 0;
}
int CDM_UpdateKeySynch(const KEKInfo* kekInfo, const unsigned char* regionId, unsigned int regionIdLen,
                       const unsigned char* cdpId, unsigned int cdpIdLen) {
    return 0;
}
int CDM_DisableKeySynch(const KEKInfo* kekInfo) {
    return 0;
}
/**
 * @param status            【OUT】 0-未开启、1-已开启
 */
int CDM_GetKeySynchStatus(const KEKInfo* kekInfo, unsigned int* status) {
    return 0;
}

int CDM_ConfigKeyNatureSize(KEKInfo* kekInfo, unsigned int flag, unsigned int projectIdNum, unsigned int domainIdNum,
                            unsigned int cdpIdNum, unsigned int regionIdNum) {
    return 0;
}
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
                         char* pubKey, unsigned int* pubKeyLen) {
    return 0;
}

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
                         unsigned int devPubKeyLen, char* clusterKey, unsigned int* clusterKeyLen) {
    return 0;
}

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
                           unsigned int* cipherClusterKeyLen) {
    return 0;
}

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
                                     unsigned int* cipherClusterKeyLen) {
    return 0;
}

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
                         const char* key, unsigned int keyLen) {
    return 0;
}
//【集群密钥结束】

//【集群管理开始】

/**
 * @brief 写入的集群归属信息到密码卡
 * @param clusterInfo               【IN】写入的信息
 * @param infoLen                   【IN】要写入的信息长度
 * @return 错误码
 */
int CDM_WriteClusterInfo(unsigned char* clusterInfo, unsigned int infoLen) {
    return 0;
}

/**
 * @brief 从密码卡中删除写入的集群归属信息
 * @return 错误码
 */
int CDM_DeleteClusterInfo(void) {
    return 0;
}

/**
 * @brief 从密码卡中读取写入的集群归属信息
 * @param clusterInfo               【OUT】读取的信息
 * @param infoLen                   【IN】要读取的信息长度
 * @return 错误码
 */
int CDM_GetClusterInfo(unsigned char* clusterInfo, unsigned int infoLen) {
    return 0;
}

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
                       unsigned int targetPubKeyLen, void* cipher, unsigned int* cipherLen) {
    return 0;
}

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
                           void* vResInfoList, unsigned int* vResInfoListLen) {
    return 0;
}

// 获取resInfoList里的成员
int CDM_GetPhysicalDeviceVoltage(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                 float* voltageType_1_2, float* voltageType_3_3, float* voltageType_12,
                                 float* voltageTypeBattery) {
    return 0;
}

int CDM_GetPhysicalDeviceTemperature(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                     float* temper) {
    return 0;
}

int CDM_GetPhysicalDevicePower(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex, float* power) {
    return 0;
}

int CDM_GetPhysicalDeviceLifespan(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                  float* lifespan) {
    return 0;
}

int CDM_GetPhysicalDeviceHealth(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                unsigned int* healthStatus) {
    return 0;
}

int CDM_GetPhysicalDeviceFirmware(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                  unsigned char* firmware, unsigned int* firmwareLen) {
    return 0;
}

int CDM_GetPhysicalDeviceLibVersion(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                    unsigned char* libraryVersion, unsigned int* libraryVersionLen) {
    return 0;
}

int CDM_GetPhysicalDeviceDeviceInfo(void* resInfoList, unsigned int resInfoListLen, unsigned int devIndex,
                                    DeviceBaseInfo* deviceInfo) {
    return 0;
}
//【集群管理结束】

//【密钥备份恢复开始】
int CDM_BackupKEK(const unsigned char* sn, unsigned int snLen, const KEKInfo* kekInfo, void* cipherKek,
                  unsigned int* cipherKekLen) {
    return 0;
}

int CDM_RestoreKEK(const unsigned char* sn, unsigned int snLen, const void* keyData, unsigned int keyDataLen) {
    return 0;
}

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
                     unsigned int* failedKeyLen) {
    return 0;
}

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
                           unsigned int keyInfoLen, AuthKeyHandle keyList, unsigned int* keyCount) {
    return 0;
}

/**
 * 结构体数据转拼接鉴权公钥
 * @param keyList                   【IN】密钥结构体数据
 * @param keyCount                  【IN】数据的个数
 * @param keyInfo                   【OUT】鉴权密钥
 * @param keyInfoLen                【IN/OUT】鉴权密钥长度
 * @return 错误码
 */
int CDM_SetVFAuthKeyStruct(AuthKeyHandle keyList, unsigned int keyCount, unsigned char* keyInfo,
                           unsigned int* keyInfoLen) {
    return 0;
}

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
                        unsigned int keyLen, unsigned char* failedKey, unsigned int* failedKeyLen) {
    return 0;
}

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
                     unsigned char* keyInfo, unsigned int* keyInfoLen) {
    return 0;
}

/**
 * @brief 删除VF中所有密钥信息
 * @param uuid                      【IN】VF的UUID
 * @param uuidLen                   【IN】VF的UUID长度
 * @return 错误码
 */
int CDM_EraseVFKeyInfo(unsigned char* uuid, unsigned int uuidLen) {
    return 0;
}
//【虚拟设备VF密钥信息结束】

//【Agent交互开始】
int CDM_ReadCardTasks(int timeout, CardTaskCallback callback) {
    return 0;
}

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
int CDM_InitDevice(const unsigned char* pass, unsigned int passLen) {
    return 0;
}

/**
 * @brief 升级固件
 * @param filePath                  【IN】固件升级文件路径
 * @param filePathLen               【IN】固件升级文件路径长度
 * @return 错误码
 */
int CDM_UpdateDevice(const char* filePath, unsigned int filePathLen) {
    return 0;
}

/**
 * @brief 升级固件后复位设备
 * @return 错误码
 */
int CDM_ResetDevice(void) {
    return 0;
}

int CDM_ImportKeyHandleCrypto(char* key, unsigned int keyLen, char* pin, unsigned int pinLen, unsigned char* keyBytes,
                              unsigned int* keyBytesLen) {
    return 0;
}

/**
 * @brief 初始化SDK实例
 * @param configPath           【IN】配置文件路径
 * @return 错误码
 */
int CDM_InitSDK(const char* configPath) {
    return 0;
}

/**
 * @brief 析构SDK实例
 */
void CDM_DeInitSDK(void) {
    
}

/**
 *  设置鉴权文件的路径
 * @param authFilePath          【IN】鉴权文件路径
 * @return 错误码
 */
int CDM_SetAuthFilePath(const char* authFilePath) {
    return 0;
}

/**
 * @brief 注册KEK到密码卡
 * @param kekInfo               【IN】要注册的KEK信息
 * @return 错误码
 */
int CDM_RegisterKEK(KEKInfo* kekInfo) {
    return 0;
}

// 【鉴权开始】
/**
 * @brief 创建鉴权密钥对
 * @param priKey                【OUT】鉴权私钥
 * @param priKeyLen             【IN/OUT】【是】鉴权私钥长度
 * @return 错误码
 */
int CDM_CreateVFKeyPair(unsigned char* priKey, unsigned int* priKeyLen) {
    return 0;
}

// 【鉴权结束】

// 【集群开始】
/**
 * @brief 导出集群公钥
 * @param flag                  【IN】要导出的设备公钥类型
 * @param sn                    【IN】sn号码对应卡
 * @param snLen                 【IN】sn的长度
 * @param pubKey                【OUT】导出的公钥
 * @param pubKeyLen             【IN/OUT】公钥的长度
 * @return 错误码
 */
int CDM_GetDevicePublicKey(unsigned int flag, const unsigned char* sn, unsigned int snLen, char* pubKey,
                           unsigned int* pubKeyLen) {
    return 0;
}
// 【集群结束】

//【DEK管理开始】
/**
 * @brief 创建随机数
 * @param length                    【IN】随机数长度
 * @param randomNum                 【OUT】随机数
 * @return 错误码
 */
int CDM_GenRandom(unsigned int length, unsigned char* randomNum) {
    return 0;
}

/**
 * @brief 创建不含明文数据密钥
 * @param algId                 【IN】DEK被加密的算法类别（0-13）,具体参考文档
 * @param iv                    【IN】初始化向量
 * @param ivLen                 【IN】初始化向量长度
 * @param dekParams             【IN】创建DEK所需的参数
 * @param keyType               【IN】指定产生的DEK密钥类型
 * @param isXts                 【IN】数据密钥是否为XTS模式专用，0与非0；影响密钥长度
 * @param outKeyBitsLen         【IN】创建的DEK的密钥比特长度
 * @param cipherKey             【OUT】对称密钥DEK密文(由KEK加密)
 * @param cipherKeyLen          【IN/OUT】DEK密文长度
 * @return 错误码
 */
int CDM_CreateDataKeyWithoutPlaintext(unsigned int algId, const unsigned char* iv, unsigned int ivLen, void* dekParams,
                                      unsigned int keyType, unsigned int isXts, unsigned int outKeyBitsLen,
                                      char* cipherKey, unsigned int* cipherKeyLen) {
    return 0;
}

/**
 * @brief 创建DEK句柄
 * @param kekInfo               【IN】kek的描述信息
 * @param pin                   【IN】用于DEK认证的PIN码
 * @param pinLen                【IN】PIN码的长度
 * @param dekParams             【OUT】DEK的句柄
 * @return 错误码
 */
int CDM_CreateDEKParams(KEKInfo* kekInfo, const unsigned char* pin, unsigned int pinLen, void** dekParams) {
    return 0;
}

/**
 * @brief 根据DEK查询出PIN信息
 * @param dekParams            【IN】DEK句柄参数
 * @param dekPin               【OUT】PIN码
 * @param dekPinLen            【IN/OUT】PIN码长度
 * @return 错误码
 */
int CDM_GetPinFromDEKParams(const void* dekParams, unsigned char* dekPin, unsigned int* dekPinLen) {
    return 0;
}

/**
 * @brief 销毁DEK句柄
 * @param dekParams            【IN】DEK句柄参数
 * @return 错误码
 */
int CDM_FreeDEKParams(void* dekParams) {
    return 0;
}

/**
 * 创建密文公私钥对
 * @param algId                【IN】KEK加密DEK的算法
 * @param iv                   【IN】初始化向量
 * @param ivLen                【IN】初始化向量长度
 * @param dekParams            【IN】创建DEK所需参数
 * @param outKeyType           【IN】秘钥对类型
 * @param outKeyBitsLen        【IN】秘钥对模长
 * @param pubKey               【OUT】公钥
 * @param pubKeyLen            【IN/OUT】公钥长度
 * @param cipherPriKey         【OUT】密文私钥
 * @param cipherPriKeyLen      【IN/OUT】密文私钥长度
 * @return 错误码
 */
int CDM_CreateDataKeyPairsWithoutPlaintext(unsigned int algId, const unsigned char* iv, unsigned int ivLen,
                                           void* dekParams, unsigned int outKeyType, unsigned int outKeyBitsLen,
                                           char* pubKey, unsigned int* pubKeyLen, char* cipherPriKey,
                                           unsigned int* cipherPriKeyLen) {
    return 0;
}

/**
 * @brief 获取SM2公钥信息
 * @param pubKey                【IN】输入的公钥字符串
 * @param x                     【OUT】SM2的x
 * @param xLen                  【IN/OUT】SM2的x的长度
 * @param y                     【OUT】SM2的y
 * @param yLen                  【IN/OUT】SM2的y的长度
 * @param bitsLen               【OUT】SM2的bits
 * @return 错误码
 */
int CDM_GetSM2PubKeyElements(char* pubKey, unsigned char* x, unsigned int* xLen, unsigned char* y, unsigned int* yLen,
                             unsigned int* bitsLen) {
    return 0;
}

/**
 * @brief 转化SM2公钥信息为公钥
 * @param x                     【IN】SM2的x
 * @param xLen                  【IN】SM2的x的长度
 * @param y                     【IN】SM2的y
 * @param yLen                  【IN】SM2的y的长度
 * @param bitsLen               【IN】SM2的bits
 * @param pubKey                【OUT】输出的公钥字符串
 * @param pubKeyLen             【IN/OUT】SM2的公钥长度
 * @return 错误码
 */
int CDM_SetSM2PubKeyElements(unsigned char* x, unsigned int xLen, unsigned char* y, unsigned int yLen,
                             unsigned int bitsLen, char* pubKey, unsigned int* pubKeyLen) {
    return 0;
}

/**
 * @brief 获取SM2签名信息
 * @param signature             【IN】输入的签名数据
 * @param signatureLen          【IN】输入的签名数据长度
 * @param r                     【OUT】SM2的r
 * @param rLen                  【IN/OUT】SM2的r的长度
 * @param s                     【OUT】SM2的r
 * @param sLen                  【IN/OUT】SM2的s的长度
 * @return 错误码
 */
int CDM_GetSM2SignatureElements(const unsigned char* signature, unsigned int signatureLen, unsigned char* r,
                                unsigned int* rLen, unsigned char* s, unsigned int* sLen) {
    return 0;
}

/**
 * @brief 转化SM2签名信息为签名数据
 * @param r                     【IN】SM2的r
 * @param rLen                  【IN】SM2的r的长度
 * @param s                     【IN】SM2的s
 * @param sLen                  【IN】SM2的s的长度
 * @param signature             【OUT】输出的SM2的签名数据
 * @param signatureLen          【IN/OUT】SM2的签名数据长度
 * @return 错误码
 */
int CDM_SetSM2SignatureElements(const unsigned char* r, unsigned int rLen, const unsigned char* s, unsigned int sLen,
                                unsigned char* signature, unsigned int* signatureLen) {
    return 0;
}

/**
 * @brief 获取SM2加密数据的信息
 * @param cipher                【IN】输入的SM2加密信息
 * @param cipherLen             【IN】输入的SM2加密信息长度
 * @param x                     【OUT】SM2的曲线点x
 * @param xLen                  【IN/OUT】SM2的曲线点x的长度
 * @param y                     【OUT】SM2的曲线点y
 * @param yLen                  【IN/OUT】SM2的曲线点y的长度
 * @param m                     【OUT】SM2加密的校验码
 * @param mLen                  【IN/OUT】SM2加密的校验码的长度
 * @param c                     【OUT】SM2加密的明文数据
 * @param cLen                  【IN/OUT】SM2加密的明文数据的长度
 * @return 错误码
 */
int CDM_GetSM2CipherElements(const unsigned char* cipher, unsigned int cipherLen, unsigned char* x, unsigned int* xLen,
                             unsigned char* y, unsigned int* yLen, unsigned char* m, unsigned int* mLen,
                             unsigned char* c, unsigned int* cLen) {
    return 0;
}

/**
 * @brief 转化SM2加密数据的信息为加密数据
 * @param x                     【IN】SM2的曲线点x
 * @param xLen                  【IN】SM2的曲线点x的长度
 * @param y                     【IN】SM2的曲线点y
 * @param yLen                  【IN】SM2的曲线点y的长度
 * @param m                     【IN】SM2加密的校验码
 * @param mLen                  【IN】SM2加密的校验码的长度
 * @param c                     【IN】SM2加密的明文数据
 * @param cLen                  【IN】SM2加密的明文数据的长度
 * @param cipher                【OUT】输出的SM2加密数据
 * @param cipherLen             【IN/OUT】输出的SM2加密数据长度
 * @return 错误码
 */
int CDM_SetSM2CipherElements(const unsigned char* x, unsigned int xLen, const unsigned char* y, unsigned int yLen,
                             const unsigned char* m, unsigned int mLen, const unsigned char* c, unsigned int cLen,
                             unsigned char* cipher, unsigned int* cipherLen) {
    return 0;
}

/**
 * @brief 获取RSA公钥信息
 * @param pubKey                【IN】输入的公钥字符串
 * @param m                     【OUT】RSA的m
 * @param mLen                  【IN/OUT】RSA的m的长度
 * @param e                     【OUT】RSA的e
 * @param eLen                  【IN/OUT】RSA的e的长度
 * @param bitsLen               【OUT】RSA的bits
 * @return 错误码
 */
int CDM_GetRSAPubKeyElements(char* pubKey, unsigned char* m, unsigned int* mLen, unsigned char* e, unsigned int* eLen,
                             unsigned int* bitsLen) {
    return 0;
}

/**
 * @brief 转化RSA公钥信息为公钥
 * @param m                     【IN】RSA的m
 * @param mLen                  【IN】RSA的m的长度
 * @param e                     【IN】RSA的e
 * @param eLen                  【IN】RSA的e的长度
 * @param bitsLen               【IN】RSA的bits
 * @param pubKey                【OUT】输出的公钥字符串
 * @param pubKeyLen             【IN/OUT】RSA的公钥长度
 * @return 错误码
 */
int CDM_SetRSAPubKeyElements(unsigned char* m, unsigned int mLen, unsigned char* e, unsigned int eLen,
                             unsigned int bitsLen, char* pubKey, unsigned int* pubKeyLen) {
    return 0;
}

/**
 * @brief 获取SM9签名主公钥信息
 * @param signMasterPubKey      【IN】输入的签名主公钥信息
 * @param xa                    【OUT】SM9的xa
 * @param xaLen                 【IN/OUT】SM9的xa的长度
 * @param xb                    【OUT】SM9的xb
 * @param xbLen                 【IN/OUT】SM9的xb的长度
 * @param ya                    【OUT】SM9的ya
 * @param yaLen                 【IN/OUT】SM9的ya的长度
 * @param yb                    【OUT】SM9的yb
 * @param ybLen                 【IN/OUT】SM9的yb的长度
 * @param bits                  【OUT】SM9的bits
 * @return 错误码
 */
int CDM_GetSM9SignPubKeyElements(const char* signMasterPubKey, unsigned char* xa, unsigned int* xaLen,
                                 unsigned char* xb, unsigned int* xbLen, unsigned char* ya, unsigned int* yaLen,
                                 unsigned char* yb, unsigned int* ybLen, unsigned int* bits) {
    return 0;
}

/**
 * @brief 转化SM9签名主公钥信息为签名主公钥
 * @param xa                    【IN】SM9的xa
 * @param xaLen                 【IN】SM9的xa的长度
 * @param xb                    【IN】SM9的xb
 * @param xbLen                 【IN/OUT】SM9的xb的长度
 * @param ya                    【IN】SM9的ya
 * @param yaLen                 【IN】SM9的ya的长度
 * @param yb                    【IN】SM9的yb
 * @param ybLen                 【IN】SM9的yb的长度
 * @param bits                  【IN】SM9的bits
 * @param signMasterPubKey      【OUT】输出的SM9签名主公钥
 * @param signMasterPubKeyLen   【IN/OUT】SM9的签名主公钥长度
 * @return 错误码
 */
int CDM_SetSM9SignPubKeyElements(const unsigned char* xa, unsigned int xaLen, const unsigned char* xb,
                                 unsigned int xbLen, const unsigned char* ya, unsigned int yaLen,
                                 const unsigned char* yb, unsigned int ybLen, unsigned int bits, char* signMasterPubKey,
                                 unsigned int* signMasterPubKeyLen) {
    return 0;
}

/**
 * @brief 获取SM9加密主公钥信息
 * @param encMasterPubKey       【IN】输入的加密主公钥信息
 * @param x                     【OUT】SM9的x
 * @param xLen                  【IN/OUT】SM9的x的长度
 * @param y                     【OUT】SM9的y
 * @param yLen                  【IN/OUT】SM9的y的长度
 * @param bits                  【OUT】SM9的bits
 * @return 错误码
 */
int CDM_GetSM9EncPubKeyElements(const char* encMasterPubKey, unsigned char* x, unsigned int* xLen, unsigned char* y,
                                unsigned int* yLen, unsigned int* bits) {
    return 0;
}

/**
 * @brief 转化SM9加密主公钥信息为加密主公钥
 * @param x                     【IN】SM9的x
 * @param xLen                  【IN】SM9的x的长度
 * @param y                     【IN】SM9的y
 * @param yLen                  【IN】SM9的y的长度
 * @param bits                  【IN】SM9的bits
 * @param encMasterPubKey       【OUT】输出的SM9加密主公钥
 * @param encMasterPubKeyLen    【IN/OUT】SM9的加密主公钥长度
 * @return 错误码
 */
int CDM_SetSM9EncPubKeyElements(const unsigned char* x, unsigned int xLen, const unsigned char* y, unsigned int yLen,
                                unsigned int bits, char* encMasterPubKey, unsigned int* encMasterPubKeyLen) {
    return 0;
}

/**
 * @brief 获取SM9签名信息
 * @param signature             【IN】输入的签名信息
 * @param signatureLen          【IN】输入的签名信息长度
 * @param x                     【OUT】SM9的x
 * @param xLen                  【IN/OUT】SM9的x的长度
 * @param y                     【OUT】SM9的y
 * @param yLen                  【IN/OUT】SM9的y的长度
 * @param h                     【OUT】SM9的h
 * @param hLen                  【IN/OUT】SM9的h的长度
 * @return 错误码
 */
int CDM_GetSM9SignatureElements(const unsigned char* signature, unsigned int signatureLen, unsigned char* x,
                                unsigned int* xLen, unsigned char* y, unsigned int* yLen, unsigned char* h,
                                unsigned int* hLen) {
    return 0;
}

/**
 * @brief 转化SM9签名信息为签名
 * @param x                     【IN】SM9的x
 * @param xLen                  【IN】SM9的x的长度
 * @param y                     【IN】SM9的y
 * @param yLen                  【IN】SM9的y的长度
 * @param h                     【IN】SM9的h
 * @param hLen                  【IN】SM9的h的长度
 * @param signature             【OUT】输出的SM9签名
 * @param signatureLen          【IN/OUT】SM9的签名长度
 * @return 错误码
 */
int CDM_SetSM9SignatureElements(const unsigned char* x, unsigned int xLen, const unsigned char* y, unsigned int yLen,
                                const unsigned char* h, unsigned int hLen, unsigned char* signature,
                                unsigned int* signatureLen) {
    return 0;
}

/**
 * @brief 获取SM9加密数据的信息
 * @param cipher                【IN】输入的SM9加密信息
 * @param cipherLen             【IN】输入的SM9加密信息长度
 * @param x                     【OUT】SM9的曲线点x
 * @param xLen                  【IN/OUT】SM9的曲线点x的长度
 * @param y                     【OUT】SM9的曲线点y
 * @param yLen                  【IN/OUT】SM9的曲线点y的长度
 * @param h                     【OUT】SM9加密的校验码
 * @param hLen                  【IN/OUT】SM9加密的校验码的长度
 * @param c                     【OUT】SM9加密的明文数据
 * @param cLen                  【IN/OUT】SM9加密的明文数据的长度
 * @return 错误码
 */
int CDM_GetSM9CipherElements(const unsigned char* cipher, unsigned int cipherLen, unsigned char* x, unsigned int* xLen,
                             unsigned char* y, unsigned int* yLen, unsigned char* h, unsigned int* hLen,
                             unsigned char* c, unsigned int* cLen) {
    return 0;
}

/**
 * @brief 转化SM9加密数据的信息为加密数据
 * @param x                     【IN】SM9的曲线点x
 * @param xLen                  【IN】SM9的曲线点x的长度
 * @param y                     【IN】SM9的曲线点y
 * @param yLen                  【IN】SM9的曲线点y的长度
 * @param h                     【IN】SM9加密的校验码
 * @param hLen                  【IN】SM9加密的校验码的长度
 * @param c                     【IN】SM9加密的明文数据
 * @param cLen                  【IN】SM9加密的明文数据的长度
 * @param cipher                【OUT】输出的SM9加密数据
 * @param cipherLen             【IN/OUT】输出的SM9加密数据长度
 * @return 错误码
 */
int CDM_SetSM9CipherElements(const unsigned char* x, unsigned int xLen, const unsigned char* y, unsigned int yLen,
                             const unsigned char* h, unsigned int hLen, const unsigned char* c, unsigned int cLen,
                             unsigned char* cipher, unsigned int* cipherLen) {
    return 0;
}

/**
 * @brief 用指定KEK加密私钥秘钥对
 * @param algId                 【IN】算法标识
 * @param iv                    【IN】初始化向量iv
 * @param ivLen                 【IN】iv长度
 * @param outKeyType            【IN】待加密密钥的类型
 * @param dekParams             【IN】dek参数
 * @param plainKey              【IN】待加密明文密钥
 * @param plainKeyLen           【IN】待加密明文密钥长度
 * @param cipherKey             【OUT】加密后的密文
 * @param cipherKeyLen          【IN/OUT】加密后密文长度
 * @return 错误码
 */
int CDM_EncryptSecretKeyWithoutPlaintext(unsigned int algId, const unsigned char* iv, unsigned int ivLen,
                                         unsigned int outKeyType, const void* dekParams, const unsigned char* plainKey,
                                         unsigned int plainKeyLen, char* cipherKey, unsigned int* cipherKeyLen) {
    return 0;
}
/**
 * @brief 创建密文主公私密钥对-SM9
 * @param algId                    【IN】密钥加密模式
 * @param dekParams                【IN】创建DEK包含的参数
 * @param outKeyType               【IN】输出秘钥对类型
 * @param pubKey                   【OUT】sm9公钥
 * @param pubKeyLen                【IN/OUT】sm9公钥长度
 * @param cipherPriKey             【IN】由KEK加密保护的SM9密文签名主私钥，签名和加密都使用SysCKey结构
 * @param cipherPriKeyLen          【IN/OUT】密文签名主私钥长度
 * @param pairG                    【OUT】加速参数
 * @param pairGLen                 【IN/OUT】加速参数长度
 * @return 错误码
 */
int CDM_CreateDataKeyPairsWithoutPlaintextSM9Master(unsigned int algId, const void* dekParams, unsigned int outKeyType,
                                                    char* pubKey, unsigned int* pubKeyLen, char* cipherPriKey,
                                                    unsigned int* cipherPriKeyLen, unsigned char* pairG,
                                                    unsigned int* pairGLen) {
    return 0;
}

/**
 * @brief 创建密文用户私钥-SM9
 * @param outKeyType              【IN】输出密钥对类型
 * @param priKeyHandle            【IN】密文签名主私钥句柄
 * @param hId                     【IN】识别符
 * @param userId                  【IN】用户id
 * @param userIdLen               【IN】用户id长度
 * @param signUserPriKey          【OUT】签名/加密用户私钥
 * @param signUserPriKeyLen       【IN/OUT】签名/加密用户私钥长度
 * @return 错误码
 */
int CDM_CreateDataKeyPairsWithoutPlaintextSM9User(unsigned int outKeyType, const void* priKeyHandle, unsigned char hId,
                                                  const unsigned char* userId, unsigned int userIdLen,
                                                  char* signUserPriKey, unsigned int* signUserPriKeyLen) {
    return 0;
}

//【DEK管理结束】

//【DEK PIN管理开始】
/**
 * @brief 创建DEK的PIN码
 * @param pin                   【OUT】PIN
 * @param pinLen                【IN/OUT】PIN码长度
 * @param recordFlag            【IN】0表示不需要记录到配置文件，非0记录到配置文件
 * @return 错误码
 */
int CDM_CreateDEKPin(char* pin, unsigned int* pinLen, unsigned int recordFlag) {
    return 0;
}

/**
 * @brief 导入pin码到SDK
 * @param pin                   【IN】 PIN
 * @param pinLen                【IN】 PIN码长度
 * @param crossCluster          【IN】 是否跨集群 非0-是, 0-否
 * @return 错误码
 */
int CDM_ImportDEKPin(const char* pin, unsigned int pinLen, unsigned int crossCluster) {
    return 0;
}

/**
 * @brief 从SDK导出pin
 * @param crossCluster          【IN】 是否跨集群 非0-是, 0-否
 * @param index                 【IN/OUT】需要导出的pin码位次
 * @param pin                   【OUT】 pin码
 * @param pinLen                【IN/OUT】 pin码长度
 * @return 错误码
 */
int CDM_ExportDEKPin(unsigned int crossCluster, unsigned int* index, char* pin, unsigned int* pinLen) {
    return 0;
}

//【DEK PIN管理结束】

//【非对称运算类开始】
/**
 * @brief 签名计算
 * @param keyType              【IN】【是】指定密钥类型
 * @param keyHandle            【IN】【是】非对称私钥句柄
 * @param hashData             【IN】【是】缓存区指针，签名数据的摘要值
 * @param hashDataLen          【IN】【是】签名数据的摘要值长度
 * @param signature            【OUT】缓存区指针，签名结果
 * @param signatureLen         【IN/OUT】【是】签名结果的长度，值为0表示预取长度
 * @return 错误码
 */
int CDM_AsymSign(unsigned int keyType, const void* keyHandle, const unsigned char* hashData, unsigned int hashDataLen,
                 unsigned char* signature, unsigned int* signatureLen) {
    return 0;
}

/**
 * 验签计算
 * @param keyType              【IN】【是】指定密钥的类型
 * @param pubKey               【IN】【是】验签SM2、RSA公钥
 * @param pubKeyLen            【IN】【是】SM2或RSA公钥(编码后)长度
 * @param hashData             【IN】【是】缓存区指针，摘要数据
 * @param hashDataLen          【IN】【是】摘要长度
 * @param signature            【IN】【是】签名结果
 * @param signatureLen         【IN】【是】签名的长度
 * @return 验签是否成功
 */
int CDM_AsymVerify(unsigned int keyType, const char* pubKey, unsigned int pubKeyLen, const unsigned char* hashData,
                   unsigned int hashDataLen, unsigned char* signature, unsigned int signatureLen) {
    return 0;
}

/**
 * @brief 签名计算
 * @param keyType              【IN】【是】指定密钥类型
 * @param keyHandle            【IN】【是】非对称私钥句柄
 * @param hashData             【IN】【是】缓存区指针，签名数据的摘要值
 * @param hashDataLen          【IN】【是】签名数据的摘要值长度
 * @param mode                 【IN】【是】mode
 * @param signature            【OUT】缓存区指针，签名结果
 * @param signatureLen         【IN/OUT】【是】签名结果的长度，值为0表示预取长度
 * @param ctx                  【IN】预留字段
 * @param ctxLen               【IN】预留字段长度
 * @return 错误码
 */
int CDM_AsymSignEx(unsigned int keyType, const void* keyHandle, const unsigned char* hashData,
                 unsigned int hashDataLen, unsigned int mode, unsigned char* signature,
                 unsigned int* signatureLen, void* ctx, unsigned int ctxLen) {
    return 0;
}

/**
 * 验签计算
 * @param keyType              【IN】【是】指定密钥的类型
 * @param pubKey               【IN】【是】验签SM2、RSA公钥
 * @param pubKeyLen            【IN】【是】SM2或RSA公钥(编码后)长度
 * @param hashData             【IN】【是】缓存区指针，摘要数据
 * @param hashDataLen          【IN】【是】摘要长度
 * @param mode                 【IN】【是】mode
 * @param signature            【IN】【是】签名结果
 * @param signatureLen         【IN】【是】签名的长度
 * @param ctx                  【IN】预留字段
 * @param ctxLen               【IN】预留字段长度
 * @return 验签是否成功
 */
int CDM_AsymVerifyEx(unsigned int keyType, const char* pubKey, unsigned int pubKeyLen, const unsigned char* hashData,
                   unsigned int hashDataLen, unsigned int mode, unsigned char* signature, unsigned int signatureLen,
                   void* ctx, unsigned int ctxLen) {
    return 0;
}

/**
 * @brief 非对称加密
 * @param keyType              【IN】【是】密钥的类型
 * @param pubKey               【IN】【是】缓冲区指针，公钥支持SM2、RSA
 * @param pubKeyLen            【IN】【是】公钥长度
 * @param data                 【IN】【是】缓冲区,非空
 * @param dataLen              【IN】【是】数据长度
 * @param encData              【OUT】缓冲区指针，密文
 * @param encDataLen           【IN/OUT】【是】密文长度，值为0时表示预取长
 * @return 错误码
 */
int CDM_AsymEncrypt(unsigned int keyType, const char* pubKey, unsigned int pubKeyLen, const unsigned char* data,
                    unsigned int dataLen, unsigned char* encData, unsigned int* encDataLen) {
    return 0;
}
/**
 * @brief 非对称解密
 * @param keyType               【IN】【是】密钥的类型
 * @param keyHandle             【IN】【是】私钥
 * @param encData               【IN】【是】密文
 * @param encDataLen            【IN】【是】密文长度
 * @param data                  【OUT】解密明文
 * @param dataLen               【IN/OUT】【是】明文长度,0代表预取长度
 * @return 错误码
 */
int CDM_AsymDecrypt(unsigned int keyType, const void* keyHandle, const unsigned char* encData, unsigned int encDataLen,
                    unsigned char* data, unsigned int* dataLen) {
    return 0;
}

/**
 * @brief 非对称加密
 * @param keyType              【IN】【是】密钥的类型
 * @param pubKey               【IN】【是】缓冲区指针，公钥支持SM2、RSA
 * @param pubKeyLen            【IN】【是】公钥长度
 * @param data                 【IN】【是】缓冲区,非空
 * @param dataLen              【IN】【是】数据长度
 * @param mode                 【IN】【是】mode
 * @param encData              【OUT】缓冲区指针，密文
 * @param encDataLen           【IN/OUT】【是】密文长度，值为0时表示预取长
 * @param ctx                  【IN】预留字段
 * @param ctxLen               【IN】预留字段长度
 * @return 错误码
 */
int CDM_AsymEncryptEx(unsigned int keyType, const char* pubKey, unsigned int pubKeyLen, const unsigned char* data,
                    unsigned int dataLen, unsigned int mode, unsigned char* encData, unsigned int* encDataLen,
                    void* ctx, unsigned int ctxLen) {
    return 0;
}

/**
 * @brief 非对称解密
 * @param keyType               【IN】【是】密钥的类型
 * @param keyHandle             【IN】【是】私钥
 * @param encData               【IN】【是】密文
 * @param encDataLen            【IN】【是】密文长度
 * @param mode                  【IN】【是】mode
 * @param data                  【OUT】解密明文
 * @param dataLen               【IN/OUT】【是】明文长度,0代表预取长度
 * @param ctx                   【IN】预留字段
 * @param ctxLen                【IN】预留字段长度
 * @return 错误码
 */
int CDM_AsymDecryptEx(unsigned int keyType, const void* keyHandle, const unsigned char* encData, unsigned int encDataLen,
                    unsigned int mode, unsigned char* data, unsigned int* dataLen, void* ctx, unsigned int ctxLen) {
    return 0;
}

/**
 * @brief SM9签名
 * @param sm9SignUserPriKeyHandle   【IN】sm9签名私钥句柄
 * @param sm9SignMasterPubKey       【IN】sm9主密钥签名公钥
 * @param sm9SignMasterPubKeyLen    【IN】sm9主密钥签名公钥长度
 * @param priKeyLen                 【IN】私钥长度
 * @param pairG                     【IN】加速参数
 * @param pairGLen                  【IN】加速参数长度
 * @param data                      【IN】待签名数据
 * @param dataLen                   【IN】数据长度
 * @param signature                 【OUT】签名结果
 * @param signatureLen              【out】签名结果长度
 * @return 错误码
 */
int CDM_AsymSignSM9(const void* sm9SignUserPriKeyHandle, const char* sm9SignMasterPubKey,
                    unsigned int sm9SignMasterPubKeyLen, const unsigned char* pairG, unsigned int pairGLen,
                    const unsigned char* data, unsigned int dataLen, unsigned char* signature,
                    unsigned int* signatureLen) {
    return 0;
}

/**
 * @brief sm9验证
 * @param hId                   【IN】识别符
 * @param userId                【IN】用户标识
 * @param userIdLen             【IN】用户标识长度
 * @param signMasterPubKey      【IN】签名主公钥
 * @param signMasterPubKeyLen   【IN】主公钥长度
 * @param pairG                 【IN】加速参数
 * @param pairGLen              【IN】加速参数长度
 * @param data                  【IN】数据
 * @param dataLen               【IN】数据长度
 * @param signature             【IN】签名
 * @param signatureLen          【IN】签名长度
 * @return 验签是否通过
 */
int CDM_AsymVerifySM9(unsigned char hId, const unsigned char* userId, unsigned int userIdLen,
                      const char* signMasterPubKey, unsigned int signMasterPubKeyLen, const unsigned char* pairG,
                      unsigned int pairGLen, const unsigned char* data, unsigned int dataLen,
                      const unsigned char* signature, unsigned int signatureLen) {
    return 0;
}

/**
 * @brief SM9加密
 * @param encMode              【IN】加密模式
 * @param hId                  【IN】识别符
 * @param userId               【IN】用户标识
 * @param userIdLen            【IN】用户标识长度
 * @param encMasterPubKey      【IN】加密主公钥
 * @param encMasterPubKeyLen   【IN】主公钥长度
 * @param pairG                【IN】加速参数
 * @param pairGLen             【IN】加速参数长度
 * @param data                 【IN】数据
 * @param dataLen              【IN】数据长度
 * @param cipher               【IN】密文
 * @param cipherLen            【IN】密文长度
 * @return 错误码
 */
int CDM_AsymEncryptSM9(unsigned int encMode, unsigned char hId, const unsigned char* userId, unsigned int userIdLen,
                       const char* encMasterPubKey, unsigned int encMasterPubKeyLen, const unsigned char* pairG,
                       unsigned int pairGLen, const unsigned char* data, unsigned int dataLen, unsigned char* cipher,
                       unsigned int* cipherLen) {
    return 0;
}

/**
 * @brief SM9解密
 * @param encMode               【IN】加密模式
 * @param userId                【IN】用户标识
 * @param userIdLen             【IN】用户标识长度
 * @param encUserPriKeyHandle   【IN】用户加密私钥
 * @param priKeyLen             【IN】用户加密私钥长度
 * @param pairG                 【IN】加速参数
 * @param pairGLen              【IN】加速参数长度
 * @param cipher                【IN】待解密的密文
 * @param cipherLen             【IN】密文长度
 * @param plainData             【OUT】解密后的明文
 * @param plainDataLen          【OUT】解密后明文长度
 * @return 错误码
 */
int CDM_AsymDecryptSM9(unsigned int encMode, const unsigned char* userId, unsigned int userIdLen,
                       const void* encUserPriKeyHandle, const unsigned char* cipher, unsigned int cipherLen,
                       unsigned char* plainData, unsigned int* plainDataLen) {
    return 0;
}
//【非对称运算类结束】

//【对称运算类开始】
/**
 * @brief 对称密钥加密
 * @param keyHandle             【IN】【是】指定的密钥句柄
 * @param keyType               【IN】密钥算法
 * @param algMode               【IN】【是】算法模式
 * @param iv                    【IN】缓存区指针
 * @param ivLen                 【IN】IV的长度
 * @param padding               【IN】Padding标志
 * @param aad                   【IN】GCM模式时存在
 * @param aadLen                【IN】AAD长度
 * @param tagLen                【IN】GCM模式指定输出tag的长度
 * @param data                  【IN】【是】缓冲区指针，存储需要加密的明文数据
 * @param dataLen               【IN】【是】明文数据的长度
 * @param encData               【OUT】密文数据缓存区指针
 * @param encDataLen            【IN/OUT】【是】密文数据长度，取值为0时表示预取长度
 * @param dataUnitLen           【IN】XTS模式下使用，用于输入数据单元长度，其余模式传0即可
 * @param tag                   【OUT】输出的tag，长度
 * @return 错误码
 */
int CDM_SymmEncrypt(const void* keyHandle, unsigned int keyType, unsigned int algMode, unsigned char* iv,
                    unsigned int ivLen, unsigned int padding, const unsigned char* aad, unsigned int aadLen,
                    unsigned int tagLen, const unsigned char* data, unsigned int dataLen, unsigned char* encData,
                    unsigned int* encDataLen, unsigned int dataUnitLen, unsigned char* tag) {
    return 0;
}

/**
 * @brief 对称密钥解密
 * @param keyHandle             【IN】【是】指定密钥句柄
 * @param keyType               【IN】密钥算法
 * @param algMode               【IN】【是】算法模式
 * @param iv                    【IN】iv缓存区指针
 * @param ivLen                 【IN】iv的长度
 * @param padding               【IN】padding标识
 * @param aad                   【IN】GCM模式时存在
 * @param aadLen                【IN】ADD长度
 * @param tag                   【IN】GCM模式时需要输入的tag
 * @param tagLen                【IN】tag参数的长度
 * @param encData               【IN】【是】密文数据缓存区指针
 * @param encDataLen            【IN】【是】密文数据长度
 * @param data                  【OUT】明文数据缓存区指针
 * @param dataLen               【IN/OUT】【是】明文数据的长度，0代表预取长度
 * @param dataUnitLen           【IN】数据单元长度
 * @return 错误码
 */
int CDM_SymmDecrypt(const void* keyHandle, unsigned int keyType, unsigned int algMode, unsigned char* iv,
                    unsigned int ivLen, unsigned int padding, const unsigned char* aad, unsigned int aadLen,
                    const unsigned char* tag, unsigned int tagLen, const unsigned char* encData,
                    unsigned int encDataLen, unsigned char* data, unsigned int* dataLen, unsigned int dataUnitLen) {
    return 0;
}

/**
 * @brief 计算MAC
 * @param keyHandle             【IN】【是】指定的密钥句柄
 * @param iv                    【IN】【是】缓冲区指针，iv
 * @param ivLen                 【IN】【是】IV的长度
 * @param data                  【IN】【是】缓存区指针，明文数据
 * @param dataLen               【IN】【是】明文数据长度
 * @param mac                   【OUT】缓存区指针，MAC值
 * @param macLen                【IN/OUT】【是】MAC长度，取0代表预取长度
 * @return 错误码
 */
int CDM_CalculateMAC(const void* keyHandle, const unsigned char* iv, unsigned int ivLen, const unsigned char* data,
                     unsigned int dataLen, unsigned char* mac, unsigned int* macLen) {
    return 0;
}

/**
 * @brief 多包运算对称加密初始化
 * @param keyHandle             【IN】【是】指定密钥句柄
 * @param keyType               【IN】【是】密钥算法
 * @param algMode               【IN】【是】算法模式标识
 * @param iv                    【IN】缓存区指针,iv
 * @param ivLen                 【IN】IV长度
 * @param padding               【IN】Padding标识
 * @param aad                   【IN】GCM模式需要
 * @param aadLen                【IN】AAD长度
 * @param tagLen                【IN】tag长度
 * @param dataUnitLen           【IN】数据单元长度，XTS模式时使用
 * @param sysCipher             【IN】【是】缓冲区指针，用于存放计算数据上下文地址
 * @return 错误码
 */
int CDM_SymmEncryptInit(const void* keyHandle, unsigned int keyType, unsigned int algMode, const unsigned char* iv,
                        unsigned int ivLen, unsigned int padding, const unsigned char* aad, unsigned int aadLen,
                        unsigned int tagLen, unsigned int dataUnitLen, void* sysCipher) {
    return 0;
}

/**
 * @brief 多包运算对称加密数据包更新
 * @param data                      【IN】【是】数据，非空
 * @param dataLen                   【IN】【是】数据长度
 * @param sysCipher                 【IN】【是】多包上下文
 * @param encData                   【OUT】数据密文
 * @param encDataLen                【IN/OUT】【是】密文长度
 * @return 错误码
 */
int CDM_SymmEncryptUpdate(const unsigned char* data, unsigned int dataLen, void* sysCipher, unsigned char* encData,
                          unsigned int* encDataLen) {
    return 0;
}

/**
 * @brief 多包运算对称加密数据包结束
 * @param data                      【IN】【是】数据,可以空
 * @param dateLen                   【IN】【是】数据长度
 * @param sysCipher                 【IN】【是】计算上下文
 * @param lastEncData               【OUT】最后一包密文数据
 * @param lastEncDataLen            【IN/OUT】最后一包密文长度
 * @param tag                       【OUT】GCM输出的tag
 * @return 错误码
 */
int CDM_SymmEncryptFinal(const unsigned char* data, unsigned int dataLen, void* sysCipher, unsigned char* lastEncData,
                         unsigned int* lastEncDataLen, unsigned char* tag) {
    return 0;
}

/**
 * @brief 多包对称加密初始化
 * @param keyHandle             【IN】指定密钥句柄
 * @param keyType               【IN】密钥算法
 * @param algMode               【IN】算法模式
 * @param iv                    【IN】缓存区指针IV
 * @param ivLen                 【IN】缓存区指针长度
 * @param padding               【IN】padding模式
 * @param aad                   【IN】GCM模式需要传入
 * @param aadLen                【IN】AAD长度
 * @param tag                   【IN】GCM模式需要指定的tag
 * @param tagLen                【IN】tag长度
 * @param dataUnitLen           【IN】数据单元长度XTS模式需要
 * @param sysCipher             【IN】数据计算上下文
 * @return 错误码
 */
int CDM_SymmDecryptInit(const void* keyHandle, unsigned int keyType, unsigned int algMode, const unsigned char* iv,
                        unsigned int ivLen, unsigned int padding, const unsigned char* aad, unsigned int aadLen,
                        unsigned char* tag, unsigned int tagLen, unsigned int dataUnitLen, void* sysCipher) {
    return 0;
}

/**
 * @brief 多包对称解密更新数据包操作
 * @param encData               【IN】【是】密文数据
 * @param encDataLen            【IN】【是】密文数据长度
 * @param sysCipher             【IN】【是】计算上下文
 * @param data                  【OUT】解密数据
 * @param dataLen               【IN/OUT】【是】解密数据长度，取值0表示预取长度
 * @return 错误码
 */
int CDM_SymmDecryptUpdate(const unsigned char* encData, unsigned int encDataLen, void* sysCipher, unsigned char* data,
                          unsigned int* dataLen) {
    return 0;
}

/**
 * @brief 多包对称解密结束
 * @param sysCipher             【IN】【是】计算上下文
 * @param encData               【IN】【是】密文数据
 * @param encDataLen            【IN】【是】密文数据长度
 * @param lastData              【OUT】明文数据
 * @param lastDataLen           【IN/OUT】【是】最后一包明文数据长度，取值0表示预取长度
 * @return 错误码
 */
int CDM_SymmDecryptFinal(void* sysCipher, const unsigned char* encData, unsigned int encDataLen,
                         unsigned char* lastData, unsigned int* lastDataLen) {
    return 0;
}

/**
 * @brief 多包MAC计算初始化
 * @param keyHandle             【IN】【是】指定的密钥句柄
 * @param iv                    【IN】【是】缓冲区指针IV
 * @param ivLen                 【IN】【是】IV的长度
 * @param sysCipher             【IN】【是】计算上下文
 * @return 错误码
 */
int CDM_CalculateMACInit(const void* keyHandle, const unsigned char* iv, unsigned int ivLen, void* sysCipher) {
    return 0;
}

/**
 * @brief 多包MAC计算更新
 * @param data                  【IN】【是】待计算的数据，缓冲区指针；非空
 * @param dataLen               【IN】【是】数据长度
 * @param sysCipher             【IN】【是】计算上下文
 * @return 错误码
 */
int CDM_CalculateMACUpdate(const unsigned char* data, unsigned int dataLen, void* sysCipher) {
    return 0;
}

/**
 * @brief 多包MAC计算结束
 * @param data                  【IN】【是】最后一包数据; 可以为空
 * @param dataLen               【IN】【是】最后一包数据长度
 * @param sysCipher             【IN】【是】计算上下文
 * @param mac                   【OUT】对应的mac值
 * @param macLen                【IN/OUT】【是】对应mac值长度, 0代表预取长度
 * @return 错误码
 */
int CDM_CalculateMACFinal(const unsigned char* data, unsigned int dataLen, void* sysCipher, unsigned char* mac,
                          unsigned int* macLen) {
    return 0;
}
//【对称运算类结束】

//【内存管理】
/**
 * @brief 内存申请
 * @param type                  【IN】【是】0-对称上下文句柄，1-杂凑上下文句柄，2-HMAC上下文句柄
 * @param handle                【OUT】【是】指向内存的句柄
 * @return 错误码
 */
int CDM_MemoryCalloc(unsigned int type, void** handle) {
    return 0;
}

/**
 * @brief 内存清零
 * @param type                   【IN】【是】0-对称上下文句柄，1-杂凑上下文句柄，2-HMAC上下文句柄
 * @param handle                 【IN】【是】内存句柄
 * @return 错误码
 */
int CDM_MemorySet(unsigned int type, void* handle) {
    return 0;
}

/**
 * @brief 内存拷贝
 * @param type                  【IN】【是】0-对称上下文句柄，1-杂凑上下文句柄，2-HMAC上下文句柄
 * @param srcHandle             【IN】【是】源内存句柄
 * @param dstHandle             【IN】【是】目标内存句柄
 * @return 错误码
 */
int CDM_MemoryCopy(unsigned int type, const void* srcHandle, void* dstHandle) {
    return 0;
}

/**
 * @brief 内存释放
 * @param type                  【IN】【是】0-对称上下文句柄，1-杂凑上下文句柄，2-HMAC上下文句柄
 * @param handle                【IN】【是】内存句柄
 * @return 错误码
 */
int CDM_MemoryFree(unsigned int type, void* handle) {
    return 0;
}
//【内存管理结束】

//【SSL传输加密】
/**
 * @brief 创建预主密钥
 * @param algId KEK加密算法
 * @param iv 初始化向量
 * @param ivLen 初始化向量长度
 * @param keyType 密钥类型
 * @param dekParams DEK的创建参数句柄
 * @param clientVer 客户端版本
 * @param pubKey 公钥
 * @param pubKeyLen 公钥长度
 * @param kekEncCmk 经kek加密的私钥
 * @param kekEncCmkLen 经kek加密的私钥长度
 * @param pubEncCmk 经公钥加密的私钥
 * @param pubEncCmkLen 经公钥加密的私钥长度
 * @return 错误码
 */
int CDM_CreatePreMasterKey(unsigned int algId, unsigned char* iv, unsigned int ivLen, unsigned int keyType,
                           void* dekParams, unsigned int clientVer, char* pubKey, unsigned int pubKeyLen,
                           char* kekEncCmk, unsigned int* kekEncCmkLen, unsigned char* pubEncCmk,
                           unsigned int* pubEncCmkLen) {
    return 0;
}

/**
 * @brief 密钥交换
 * @param keyType 密钥类型
 * @param priKeyHandle 私钥句柄
 * @param encData 加密的数据
 * @param encDataLen 加密的数据长度
 * @param cipherKey 协商的密钥
 * @param cipherKeyLen 协商的密钥长度
 * @return 错误码
 */
int CDM_PreMasterKeyExchange(unsigned int keyType, void* priKeyHandle, unsigned char* encData, unsigned int encDataLen,
                             char* cipherKey, unsigned int* cipherKeyLen) {
    return 0;
}

/**
 * @brief 密钥交换 - SM2方式
 * @param flag 己方标识
 * @param ownPubKey 己方公钥
 * @param ownPubKeyLen 己方公钥长度
 * @param ownPriKeyHandle 己方私钥句柄
 * @param ownTmpPubKey 己方临时公钥
 * @param ownTmpPubKeyLen 己方临时公钥长度
 * @param ownTmpPriKeyHandle 己方临时私钥句柄
 * @param keyBits 密钥模长
 * @param sponsorId 发起方ID
 * @param sponsorIdLen 发起方ID长度
 * @param responseId 接收方ID
 * @param responseIdLen 接收方ID长度
 * @param responsePubKey 接收方公钥
 * @param responsePubKeyLen 接收方公钥长度
 * @param responseTmpPubKey 接收方临时公钥
 * @param responseTmpPubKeyLen 接收方临时公钥长度
 * @param cipherKey 协商的私钥
 * @param cipherKeyLen 协商的私钥长度
 * @return 错误码
 */
int CDM_PreMasterKeyExchangeSM2STD(unsigned int flag, char* ownPubKey, unsigned int ownPubKeyLen, void* ownPriKeyHandle,
                                   char* ownTmpPubKey, unsigned int ownTmpPubKeyLen, void* ownTmpPriKeyHandle,
                                   unsigned int keyBits, unsigned char* sponsorId, unsigned int sponsorIdLen,
                                   unsigned char* responseId, unsigned int responseIdLen, char* responsePubKey,
                                   unsigned int responsePubKeyLen, char* responseTmpPubKey,
                                   unsigned int responseTmpPubKeyLen, char* cipherKey, unsigned int* cipherKeyLen) {
    return 0;
}

/**
 * @brief 获取SSL密钥派生KeyMaterials结构体信息
 * @param keyMaterials          【IN】输入的KeyMaterials结构体
 * @param KeyMaterialsLen       【IN】输入的KeyMaterials结构体长度
 * @param keyHandle             【OUT】KeyMaterials的密钥句柄
 * @param label                 【OUT】KeyMaterials的标签
 * @param labelLen              【IN/OUT】KeyMaterials的标签长度
 * @param serverRandom          【OUT】KeyMaterials的服务端随机数
 * @param serverRandomLen       【IN/OUT】KeyMaterials的服务端随机数长度
 * @param clientRandom          【OUT】KeyMaterials的客户端随机数
 * @param clientRandomLen       【IN/OUT】KeyMaterials的客户端随机数长度
 * @param sslHash               【OUT】KeyMaterials的哈希值
 * @param sslHashLen            【IN/OUT】KeyMaterials的哈希值长度
 * @return 错误码
 */
int CDM_GetKeyMaterialsElements(const unsigned char* keyMaterials, unsigned int KeyMaterialsLen, void** keyHandle,
                                char* label, unsigned int* labelLen, unsigned char* serverRandom,
                                unsigned int* serverRandomLen, unsigned char* clientRandom,
                                unsigned int* clientRandomLen, unsigned char* sslHash, unsigned int* sslHashLen) {
    return 0;
}

/**
 * @brief 通过SSL密钥派生的KeyMaterials结构体信息产生KeyMaterials结构体
 * @param keyHandle             【IN】KeyMaterials的密钥句柄
 * @param label                 【IN】】KeyMaterials的标签
 * @param labelLen              【IN】KeyMaterials的标签长度
 * @param serverRandom          【IN】】KeyMaterials的服务端随机数
 * @param serverRandomLen       【IN】KeyMaterials的服务端随机数长度
 * @param clientRandom          【IN】】KeyMaterials的客户端随机数
 * @param clientRandomLen       【IN】KeyMaterials的客户端随机数长度
 * @param sslHash               【IN】】KeyMaterials的哈希值
 * @param sslHashLen            【IN】KeyMaterials的哈希值长度
 * @param keyMaterials          【OUT】输出的KeyMaterials结构体
 * @param KeyMaterialsLen       【OUT】输出的KeyMaterials结构体长度
 * @return 错误码
 */
int CDM_SetKeyMaterialsElements(void* keyHandle, const char* label, unsigned int labelLen,
                                const unsigned char* serverRandom, unsigned int serverRandomLen,
                                const unsigned char* clientRandom, unsigned int clientRandomLen,
                                const unsigned char* sslHash, unsigned int sslHashLen, unsigned char* keyMaterials,
                                unsigned int* KeyMaterialsLen) {
    return 0;
}

/**
 * @brief 获取SSL密钥派生WorkKeyLen结构体信息
 * @param workKeyLen            【IN】输入的WorkKeyLen结构体
 * @param workKeyLenLength      【IN】输入的WorkKeyLen结构体长度
 * @param macKeyLenClient       【OUT】WorkKeyLen的客户端哈希密钥长度
 * @param macKeyLenServer       【OUT】WorkKeyLen的服务端哈希密钥长度
 * @param encKeyLenClient       【OUT】WorkKeyLen的客户端加密密钥长度
 * @param encKeyLenServer       【OUT】WorkKeyLen的服务端加密密钥长度
 * @param macKeyTypeClient      【OUT】WorkKeyLen的客户端哈希密钥类型
 * @param macKeyTypeServer      【OUT】WorkKeyLen的服务端哈希密钥类型
 * @param encKeyTypeClient      【OUT】WorkKeyLen的客户端加密密钥类型
 * @param encKeyTypeServer      【OUT】WorkKeyLen的服务端加密密钥类型
 * @param ivClient              【OUT】WorkKeyLen的客户端随机数长度
 * @param ivServer              【OUT】WorkKeyLen的服务端随机数长度
 * @return 错误码
 */
int CDM_GetWorkKeyLenElements(const unsigned char* workKeyLen, unsigned int workKeyLenLength,
                              unsigned int* macKeyLenClient, unsigned int* macKeyLenServer,
                              unsigned int* encKeyLenClient, unsigned int* encKeyLenServer,
                              unsigned int* macKeyTypeClient, unsigned int* macKeyTypeServer,
                              unsigned int* encKeyTypeClient, unsigned int* encKeyTypeServer, unsigned int* ivClient,
                              unsigned int* ivServer) {
    return 0;
}

/**
 * @brief 通过SSL密钥派生的workKeyLen结构体信息产生workKeyLen结构体
 * @param macKeyLenClient       【IN】WorkKeyLen的客户端哈希密钥长度
 * @param macKeyLenServer       【IN】WorkKeyLen的服务端哈希密钥长度
 * @param encKeyLenClient       【IN】WorkKeyLen的客户端加密密钥长度
 * @param encKeyLenServer       【IN】WorkKeyLen的服务端加密密钥长度
 * @param macKeyTypeClient      【IN】WorkKeyLen的客户端哈希密钥类型
 * @param macKeyTypeServer      【IN】WorkKeyLen的服务端哈希密钥类型
 * @param encKeyTypeClient      【IN】WorkKeyLen的客户端加密密钥类型
 * @param encKeyTypeServer      【IN】WorkKeyLen的服务端加密密钥类型
 * @param ivClient              【IN】WorkKeyLen的客户端随机数长度
 * @param ivServer              【IN】WorkKeyLen的服务端随机数长度
 * @param workKeyLen            【OUT】输出的WorkKeyLen结构体
 * @param workKeyLenLength      【IN/OUT】输出的WorkKeyLen结构体长度
 * @return
 */
int CDM_SetWorkKeyLenElements(unsigned int macKeyLenClient, unsigned int macKeyLenServer, unsigned int encKeyLenClient,
                              unsigned int encKeyLenServer, unsigned int macKeyTypeClient,
                              unsigned int macKeyTypeServer, unsigned int encKeyTypeClient,
                              unsigned int encKeyTypeServer, unsigned int ivClient, unsigned int ivServer,
                              unsigned char* workKeyLen, unsigned int* workKeyLenLength) {
    return 0;
}
/**
 * @brief SSL密钥派生
 * @param algId 算法标识
 * @param keyMaterials 派生材料
 * @param workKeyLen 工作密钥长度
 * @param key 最终输出 （根据标签去截断）
 * @param keyLen 输出长度
 * @return 错误码
 */
int CDM_PRF(unsigned int algId, KeyMaterials* keyMaterials, WorkKeyLen* workKeyLen, unsigned char* key,
            unsigned int* keyLen) {
    return 0;
}
//【SSL传输加密结束】

// 【杂凑运算类】
/**
 * @brief 单包数据杂凑运算
 * @param algId                 【IN】【是】算法标识
 * @param pubKey                【IN】SM2公钥，algId为SM3时需要
 * @param pubKeyLen             【IN】SM2公钥长度
 * @param id                    【IN】签名者的ID，algId为SM3时需要
 * @param idLen                 【IN】签名者ID的长度
 * @param data                  【IN】【是】数据
 * @param dataLen               【IN】【是】数据长度
 * @param hash                  【OUT】杂凑数据
 * @param hashLen               【IN/OUT】【是】杂凑数据长度，取值为0时，表示预取长度
 * @return 错误码
 */
int CDM_Hash(unsigned int algId, const char* pubKey, unsigned int pubKeyLen, const unsigned char* id,
             unsigned int idLen, const unsigned char* data, unsigned int dataLen, unsigned char* hash,
             unsigned int* hashLen) {
    return 0;
}

/**
 * @brief 多包运算初始化
 * @param algId                【IN】【是】算法标识
 * @param pubKey               【IN】【是】SM2公钥
 * @param pubKeyLen            【IN】SM2公钥长度
 * @param id                   【IN】签名者的ID值
 * @param idLen                【IN】签名者的ID值长度
 * @param hashContext          【IN/OUT】【是】杂凑计算上下文
 * @return 错误码
 */
int CDM_HashInit(unsigned int algId, const char* pubKey, unsigned int pubKeyLen, const unsigned char* id,
                 unsigned int idLen, void* hashContext) {
    return 0;
}

/**
 * @brief 多包杂凑运算数据包更新
 * @param data                  【IN】【是】数据
 * @param dataLen               【IN】【是】数据长度
 * @param hashContext           【IN/OUT】【是】杂凑运算上下文
 * @return 错误码
 */
int CDM_HashUpdate(const unsigned char* data, unsigned int dataLen, void* hashContext) {
    return 0;
}

/**
 * @brief 多包杂凑运算数据包结束
 * @param hashContext          【IN】【是】多包杂凑运算上下文
 * @param hash                 【OUT】最后一包多包杂凑计算结果
 * @param hashLen              【IN/OUT】【是】多包杂凑计算结果长度，取值0代表预取长度
 * @return 错误码
 */
int CDM_HashFinal(void* hashContext, unsigned char* hash, unsigned int* hashLen) {
    return 0;
}

/**
 * @brief 单包hmac
 * @param keyHandle            【IN】【是】密钥句柄
 * @param data                 【IN】【是】明文数据
 * @param dataLen              【IN】【是】明文数据长度
 * @param mac                  【OUT】计算hmac结果
 * @param macLen               【IN/OUT】【是】 hmac长度，取值为0表示预取长度
 * @return 错误码
 */
int CDM_CalculateHMAC(const void* keyHandle, const unsigned char* data, unsigned int dataLen, unsigned char* mac,
                      unsigned int* macLen) {
    return 0;
}

/**
 * @brief 多包hmac初始化
 * @param keyHandle            【IN】【是】密钥句柄
 * @param hmacContext          【IN】【是】计算上下文
 * @return 错误码
 */
int CDM_HMACInit(const void* keyHandle, void* hmacContext) {
    return 0;
}

/**
 * @brief 多包hmac更新
 * @param data                 【IN】【是】明文数据
 * @param dataLen              【IN】【是】明文数据长度
 * @param hmacContext          【IN/OUT】【是】计算上下文
 * @return 错误码
 */
int CDM_HMACUpdate(const unsigned char* data, unsigned int dataLen, void* hmacContext) {
    return 0;
}

/**
 * @brief 多包hmac结束
 * @param hmacContext          【IN】【是】计算上下文
 * @param hmac                 【OUT】计算结果
 * @param hmacLen              【IN/OUT】【是】计算结果长度，取值0表示预取长度
 * @return 错误码
 */
int CDM_HMACFinal(void* hmacContext, unsigned char* hmac, unsigned int* hmacLen) {
    return 0;
}

/**
 * @brief PBKDF2运算
 * @param algId                 【IN】【是】杂凑算法id
 * @param pass                  【IN】【是】口令
 * @param passLen               【IN】【是】口令长度
 * @param salt                  【IN】【是】盐值
 * @param saltLen               【IN】【是】盐值长度
 * @param count                 【IN】【是】迭代次数
 * @param keyLen                【IN】【是】期望长度
 * @param result                【OUT】【是】计算结果
 * @return 错误码
 */
int CDM_PBKDF2(unsigned int algId, const unsigned char* pass, unsigned int passLen, const unsigned char* salt,
               unsigned int saltLen, unsigned int count, unsigned int keyLen, unsigned char* result) {
    return 0;
}
// 【杂凑运算类结束】

// 【DEK句柄管理开始】
/**
 * @brief 创建密钥句柄
 * @param key                       【IN】【是】密文密钥DEK
 * @param keyLen                    【IN】【是】密文密钥长度
 * @param pin                       【IN】保护DEK的DekPin编码结果
 * @param pinLen                    【IN】DekPin编码结果长度
 * @param keyHandle                 【OUT】【是】DEK密钥句柄
 * @return 错误码
 */
int CDM_ImportKeyHandle(const char* key, unsigned int keyLen, const char* pin, unsigned int pinLen, void** keyHandle) {
    return 0;
}

/**
 * @brief 创建明文密钥句柄
 * @param key                       【IN】【是】密文密钥DEK
 * @param keyLen                    【IN】【是】密文密钥长度
 * @param keyType                   【IN】【是】密文类型
 * @param keyHandle                 【OUT】【是】DEK密钥句柄
 * @param ctx                       【IN】预留字段
 * @param ctxLen                    【IN】预留字段长度
 * @return 错误码
 */
int CDM_ImportPlainKeyHandle(const char* key, unsigned int keyLen, unsigned int keyType,
                void* ctx, unsigned int ctxLen, void** keyHandle) {
    return 0;
 }

/**
 * @brief 销毁DEK句柄
 * @param keyHandle                 【IN】【是】DEK句柄
 * @return 错误码
 */
int CDM_DestroyKeyHandle(void* keyHandle) {
    return 0;
}

/**
 * @brief 校验传入的句柄是否和需要的算法一致
 * @param keyHandle                 【IN】【是】DEK句柄
 * @param dataKeyType               【IN】【是】所需的算法ID
 * @return 1为一致，0为不一致
 */
int CDM_CheckKeyHandleKeyType(void* keyHandle, unsigned int dataKeyType) {
    return 0;
}
// 【DEK句柄管理结束】

// 【JDK适配】
/**
 * @brief 从私钥计算公钥
 * @param keyHandle                 【IN】私钥
 * @param priKeyLen                 【IN】私钥长度
 * @param pubKey                    【OUT】返回公钥
 * @param pubKeyLen                 【IN/OUT】返回的公钥长度
 * @return 错误码
 */
int CDM_CalculatePubKey(const void* keyHandle, char* pubKey, unsigned int* pubKeyLen) {
    return 0;
}

/**
 * @brief 使用集群密钥2（数据加密）加密数据, 仅用于加密KMS[AK][SK]
 * @param data                      【IN】明文数据
 * @param dataLen                   【IN】明文数据长度
 * @param encData                   【OUT】密文数据
 * @param encDataLen                【IN/OUT】密文长度
 */
int CDM_EncryptLocalData(const unsigned char* data, unsigned int dataLen, char* encData, unsigned int* encDataLen) {
    return 0;
}

/**
 * @brief 根据dek返回对应保存在配置文件中的
 * @param key                       【IN】 dek
 * @param keyLen                    【IN】 dek的长度
 * @param pin                       【OUT】 dek对应pin
 * @param pinLen                    【IN/OUT】pin的长度
 * @return 错误码
 */
int CDM_GetPinOfDek(const char* key, unsigned int keyLen, char* pin, unsigned int* pinLen) {
    return 0;
}

/**
 * @brief 将明文的pin转换为集群密钥加密后的pin
 * @param pin                               【IN/OUT】输入明文的pin输出集群密钥加密后的pin
 * @param pinLen                            【IN】PIN的长度，明文与密文长度一致
 * @return
 */
int CDM_TransPlainPinToClusterEncrypted(char* pin, unsigned int pinLen) {
    return 0;
}

/**
 * @brief 获取密文头
 * @param buf        【OUT】输出密文头
 * @param bufLen     【OUT】输出密文头的长度
 * @return 错误码
 */
int CDM_GetCipherHead(unsigned char* buf, unsigned int *bufLen) {
    return 0;
}
