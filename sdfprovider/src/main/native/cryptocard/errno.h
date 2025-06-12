#ifndef CRYPTOCARDSDK_ERRNO_H
#define CRYPTOCARDSDK_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

/*标准错误码定义*/
#define SDR_OK 0x0 /*成功*/
#define SDR_BASE 0x01000000
#define SDR_UNKNOWERR (SDR_BASE + 0x00000001) /*未知错误*/
#define SDR_NOTSUPPORT (SDR_BASE + 0x00000002) /*不支持*/
#define SDR_COMMFAIL (SDR_BASE + 0x00000003) /*通信错误*/
#define SDR_HARDFAIL (SDR_BASE + 0x00000004) /*硬件错误*/
#define SDR_OPENDEVICE (SDR_BASE + 0x00000005) /*打开设备错误*/
#define SDR_OPENSESSION (SDR_BASE + 0x00000006) /*打开会话句柄错误*/
#define SDR_PARDENY (SDR_BASE + 0x00000007) /*权限不满足*/
#define SDR_KEYNOTEXIST (SDR_BASE + 0x00000008) /*密钥不存在*/
#define SDR_ALGNOTSUPPORT (SDR_BASE + 0x00000009) /*不支持的算法*/
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A) /*不支持的算法模式*/
#define SDR_PKOPERR (SDR_BASE + 0x0000000B) /*公钥运算错误*/
#define SDR_SKOPERR (SDR_BASE + 0x0000000C) /*私钥运算错误*/
#define SDR_SIGNERR (SDR_BASE + 0x0000000D) /*签名错误*/
#define SDR_VERIFYERR (SDR_BASE + 0x0000000E) /*验证错误*/
#define SDR_SYMOPERR (SDR_BASE + 0x0000000F) /*对称运算错误*/
#define SDR_STEPERR (SDR_BASE + 0x00000010) /*步骤错误*/
#define SDR_FILESIZEERR (SDR_BASE + 0x00000011) /*文件大小错误或输入数据长度非法*/
#define SDR_FILENOEXIST (SDR_BASE + 0x00000012) /*文件不存在*/
#define SDR_FILEOFSERR (SDR_BASE + 0x00000013) /*文件操作偏移量错误*/
#define SDR_KEYTYPEERR (SDR_BASE + 0x00000014) /*密钥类型错误*/
#define SDR_KEYERR (SDR_BASE + 0x00000015) /*密钥错误*/

/*附加错误码定义*/
#define SDR_ARGUMENTERR (SDR_BASE + 0x00000016) /*参数错误*/
#define SDR_MEMALLOCERR (SDR_BASE + 0x00000017) /*内存创建错误*/
#define SDR_MEMCPYERR (SDR_BASE + 0x00000018) /*内存创建错误*/
#define SDR_MEMNOTENOUGH (SDR_BASE + 0x00000019) /*内存不够错误*/
#define SDR_FILEACCESSERR (SDR_BASE + 0x00000020) /*文件权限不满足*/
#define SDR_CONFIGINITERR (SDR_BASE + 0x00000021) /*配置模块初始化失败*/
#define SDR_CARDINITERR (SDR_BASE + 0x00000023) /*卡管理器模块初始化失败*/
#define SDR_PIN_REFUSED (SDR_BASE + 0x00000024) /*pin码校验失败，拒绝调用接口*/
#define SDR_TIMEOUT (SDR_BASE + 0x00000025) /*密码卡超时错误*/
#define SDR_TASK_DATA_INVALID (SDR_BASE + 0x00000026) /*密码卡任务错误*/
#define SDR_POLL_ERROR (SDR_BASE + 0x00000027) /*密码卡poll机制错误*/
#define SDR_AUTH_KEY_LIMIT (SDR_BASE + 0x00000028) /*当前VF承载的鉴权数量达上限5个*/
#define SDR_AUTH_REPEAT (SDR_BASE + 0x00000029) /*鉴权密钥已经存在*/
#define SDR_AUTH_IMPORT_CARD_ERR (SDR_BASE + 0x00000030) /*鉴权公钥导入卡失败*/
#define SDR_AUTH_ERR (SDR_BASE + 0x00000031) /*鉴权失败*/
#define SDR_FILE_LOCK_ERR (SDR_BASE + 0x00000038) /*文件加锁解锁失败*/
#define SDR_CONFIG_REFRESH_ERR (SDR_BASE + 0x00000033) /*文件加锁解锁失败*/
#define SDR_KMS_CONNECT_ERR (SDR_BASE + 0x00000034) /*kms服务连接失败*/
#define SDR_KMS_INIT_ERR (SDR_BASE + 0x00000035) /*sdk没有初始化、kms_client初始化失败*/
#define SDR_KMS_RESULT_ERR (SDR_BASE + 0x00000036) /*kms 返回的内容没通过sdk的校验（key的长度、pin的长度）等*/
#define SDR_PCAP_IO_ERR (SDR_BASE + 0x00000037) /*pcap发送数据io错误*/

/*附加错误码-日志模块*/
#define SDR_LOG_ERR (SDR_BASE + 0x00100000) /*日志模块错误*/
#define SDR_LOGINITERR (SDR_LOG_ERR + 0x00000001) /*zlog模块初始化失败*/
#define SDR_LOGLEVELERR (SDR_LOG_ERR + 0x00000002) /*日志模块等级配置错误*/
#define SDR_LOGPATHERR (SDR_LOG_ERR + 0x00000003) /*日志模块路径配置错误*/
#define SDR_LOGFILESIZEERR (SDR_LOG_ERR + 0x00000004) /*日志模块文件大小配置错误*/
#define SDR_LOGROTATEERR (SDR_LOG_ERR + 0x00000005) /*日志模块轮转周期错误*/
#define SDR_REFRESH_LOG_ERR (SDR_LOG_ERR + 0x00000006) /*多进程使用配置文件，读写文件前刷新日志错误*/
#define SDR_LOGFROMATERR (SDR_LOG_ERR + 0x00000007) /*日志模块模板错误*/
/*附加错误码-配置模块*/
#define SDR_CONFIG_ERR (SDR_BASE + 0x00200000) /*配置模块错误*/
#define SDR_JSON_ERR (SDR_CONFIG_ERR + 0x00000001) /*配置文件格式错误*/
#define SDR_FLASH_CONFIG_ERR (SDR_CONFIG_ERR + 0x00000002) /*刷新配置文件错误*/
#define SDR_AUTH_FILE_ACCESS (SDR_CONFIG_ERR + 0x00000003) /*鉴权文件权限问题*/
#define SDR_KMS_LEAK_ERR (SDR_CONFIG_ERR + 0x00000004) /*KMS 配置确实*/
/*附加错误码-用户传参*/
#define SDR_PARAM_ERR (SDR_BASE + 0x00300000) /*用户传参错误*/
#define SDR_PARAM_SIZE_ERR (SDR_PARAM_ERR + 0x00000001) /*用户外部申请内存太小, 已经修改必须长度*/

/*附加错误码-卡适配器模块*/
#define SDR_CARD_ERR (SDR_BASE + 0x00400000) /*卡管理器模块错误*/
#define SDR_CARD_DEVIC_EERR (SDR_CARD_ERR + 0x00000001) /*全部卡设备无法开启新会话*/
#define SDR_SDKNULL (SDR_CARD_ERR + 0x00000002) /*SDK已经释放*/
#define SDR_SDKPINLIMIT (SDR_CARD_ERR + 0x00000003) /*PIN导入超过上限*/
#define SDR_SN_NOT_FOUND (SDR_CARD_ERR + 0x00000004) /*SN号未找到*/

/*附加错误码-设备打开、会话打开*/
#define SDR_CARD_DEVICE_ERR (SDR_BASE + 0x00000032) /*指定SN对应的设备无法打开、未指定SN时全部的设备无法打开*/
#define SDR_CREATE_SESSION_ERR (SDR_BASE + 0x000000034)  //创建会话失败

/*编解码*/
#define SDR_BYTE_DECODE_ERR (SDR_BASE + 0x000000040)  // 16进制解码错误
#define SDR_BYTE_ENCODE_ERR (SDR_BASE + 0x000000041)  // 16进制编码错误
#define SDR_STRUCT_DECODE_ERR (SDR_BASE + 0x000000042)  // 字符串转struct失败

/*SDK生命周期*/
#define SDR_INIT_CONFIG_PATH_ERR (SDR_BASE + 0x000000049)  //SDK配置文件传参为空、环境变量为空
#define SDR_INIT_DEFAULT_PIN_ERR (SDR_BASE + 0x000000050)  //SDK初始化创建默认PIN失败
#define SDR_INIT_CARD_MANAGER_ERR (SDR_BASE + 0x000000051)  //SDK初始化创建密码卡管理器失败
#define SDR_INIT_CONFIG_ERR (SDR_BASE + 0x00000052) /*配置模块初始化失败*/
/*调用卡VF接口失败*/
#define SDR_GENERATE_RANDOM_ERR (SDR_BASE + 0x000010002)  //创建随机数失败
#define SDR_ASYM_SIGN_ERR (SDR_BASE + 0x000010003)  //非对称签名失败
#define SDR_ASYM_VERIFY_ERR (SDR_BASE + 0x000010004)  //非对称验证失败
#define SDR_ASYM_ENCRYPT_ERR (SDR_BASE + 0x000010005)  //非对称公钥加密失败
#define SDR_ASYM_DECRYPT_ERR (SDR_BASE + 0x000010006)  //非对称私钥解密失败
#define SDR_SYMM_ENCRYPT_ERR (SDR_BASE + 0x000010007)  //对称加密失败
#define SDR_SYMM_DECRYPT_ERR (SDR_BASE + 0x000010008)  //对称解密失败
#define SDR_MAC_ERR (SDR_BASE + 0x000010009)  //计算MAC失败
#define SDR_SYMM_ENCRYPT_INIT_ERR (SDR_BASE + 0x000010010)  //多包对称加密初始化失败
#define SDR_SYMM_ENCRYPT_UPDATE_ERR (SDR_BASE + 0x000010011)  //多包对称加密更新失败
#define SDR_SYMM_ENCRYPT_FINAL_ERR (SDR_BASE + 0x000010012)  //多包对称加密结束失败
#define SDR_SYMM_DECRYPT_INIT_ERR (SDR_BASE + 0x000010013)  //多包对称解密初始化失败
#define SDR_SYMM_DECRYPT_UPDATE_ERR (SDR_BASE + 0x000010014)  //多包对称解密更新失败
#define SDR_SYMM_DECRYPT_FINAL_ERR (SDR_BASE + 0x000010015)  //多包对称解密结束失败
#define SDR_MAC_INIT_ERR (SDR_BASE + 0x000010016)  //多包MAC初始化错误
#define SDR_MAC_UPDATE_ERR (SDR_BASE + 0x000010017)  //多包MAC更新失败
#define SDR_MAC_FINAL_ERR (SDR_BASE + 0x000010018)  //多包MAC结束失败
#define SDR_MEM_CALLOC_ERR (SDR_BASE + 0x000010019)  //多包内存申请失败
#define SDR_MEM_COPY_ERR (SDR_BASE + 0x000010020)  //多包内存拷贝失败
#define SDR_MEM_SET_ERR (SDR_BASE + 0x000010021)  //多包内存设置失败
#define SDR_MEM_FREE_ERR (SDR_BASE + 0x000010022)  //多包内存释放失败
#define SDR_CREATE_PRE_MASTER_ERR (SDR_BASE + 0x000010023)  //ssl创建预先主密钥失败
#define SDR_PRE_MASTER_EXCHANGE_ERR (SDR_BASE + 0x000010024)  //ssl预先主密钥交换失败
#define SDR_PRE_MASTER_EXCHANGE_SM2STD_ERR (SDR_BASE + 0x000010025)  //ssl预先主密钥交换SM2STD失败
#define SDR_HASH_ERR (SDR_BASE + 0x000010026)  //杂凑hash失败
#define SDR_HASH_INIT_ERR (SDR_BASE + 0x000010027)  //杂凑多包hash初始化失败
#define SDR_HASH_UPDATE_ERR (SDR_BASE + 0x000010028)  //杂凑多包hash更新失败
#define SDR_HASH_FINAL_ERR (SDR_BASE + 0x000010029)  //杂凑多包hash结束失败
#define SDR_PBKDF2_ERR (SDR_BASE + 0x000010030)  //PBKDF2计算失败
#define SDR_HMAC_INIT_ERR (SDR_BASE + 0x000010031)  //多包HMAC初始化错误
#define SDR_HMAC_UPDATE_ERR (SDR_BASE + 0x000010032)  //多包HMAC更新失败
#define SDR_HMAC_FINAL_ERR (SDR_BASE + 0x000010033)  //多包HMAC结束失败
#define SDR_HMAC_ERR (SDR_BASE + 0x000010034)  //单包HMAC失败
#define SDR_IMPORT_KEY_HANDLE_ERR (SDR_BASE + 0x000010035)  //导入DEK句柄失败
#define SDR_DESTROY_KEY_HANDLE_ERR (SDR_BASE + 0x000010036)  //销毁DEK句柄失败
#define SDR_CREATE_PIN_ERR (SDR_BASE + 0x000010037)  //创建PIN失败
#define SDR_IMPORT_PIN_ERR (SDR_BASE + 0x000010038)  //导入PIN失败
#define SDR_EXPORT_PIN_ERR (SDR_BASE + 0x000010039)  //导出PIN失败
#define SDR_SET_PIN_ERR (SDR_BASE + 0x000010040)  //设置开启PIN功能失败
#define SDR_CREATE_AUTH_KEY_ERR (SDR_BASE + 0x000010041)  //创建鉴权密钥对失败
#define SDR_CALCULATE_PUBKEY_ERR (SDR_BASE + 0x000010042)  //由私钥计算获得公钥失败
#define SDR_DECRYPT_LOCAL_DATA (SDR_BASE + 0x000010043)  // 本地解密失败
#define SDR_CREATE_TOKEN_ERR  (SDR_BASE + 0x000010044)  // 创建token失败
/*调用卡PF接口失败*/
#define SDR_REGISTER_KEK_ERR (SDR_BASE + 0x000020001)  //注册kek失败
#define SDR_GET_DEVICE_PUBKEY_ERR (SDR_BASE + 0x000020002)  //获得设备公钥失败
#define SDR_CREATE_DEK_PARAMS_ERR (SDR_BASE + 0x000020003)  //创建DEK参数失败
#define SDR_GET_PIN_FROM_PARAMS_ERR (SDR_BASE + 0x000020004)  //DEK参数中获取pin失败
#define SDR_TRANS_CDP_KEY_DEV_ERR (SDR_BASE + 0x000020005)  // 使用管理集群设备公钥转加密, KEK加密的集群密钥失败
#define SDR_TRANS_CDP_KEY_KEK_ERR (SDR_BASE + 0x000020006)  // 使用KEK转加密, 业务集群设备公钥加密的集群密钥失败
#define SDR_CREATE_DEK_ERR (SDR_BASE + 0x000020007)  // 创建对称类型DEK失败
#define SDR_CREATE_DEK_PAIR_ERR (SDR_BASE + 0x000020008)  // 创建对称类型DEK失败
#define SDR_BACKUP_KEK (SDR_BASE + 0x000020009)  // 备份kek失败
#define SDR_ENCRYPT_PLAIN_DEK_ERR (SDR_BASE + 0x000020010)  // 加密明文DEK失败
#define SDR_EXPORT_KEK_ERR (SDR_BASE + 0x000020011)  // 导出kek失败
#define SDR_EXPORT_CDP_KEY_ERR (SDR_BASE + 0x000020012)  // 使用设备公钥导出集群密钥失败
#define SDR_IMPORT_CDP_KEY_ERR (SDR_BASE + 0x000020013)  // 导设备公钥加密的入集群密钥失败
#define SDR_ENABLE_KEY_SYNCH_ERR (SDR_BASE + 0x00020014) // 配置并开启密钥同步失败
#define SDR_DISABLE_KEY_SYNCH_ERR (SDR_BASE + 0x00020015) // 配置并开启密钥同步失败
#define SDR_UPDATE_KEY_SYNCH_ERR (SDR_BASE + 0x00020016) // 配置并开启密钥同步失败
#define SDR_GET_KEY_SYNCH_STATUS_ERR (SDR_BASE + 0x00020017) // 配置并开启密钥同步失败

/*协议错误码定义*/
#define PROTOCOL_BASE 0x02000000
#define PROTOCOL_CMDERR (PROTOCOL_BASE + 0x00000001) /*命令错误*/
#define PROTOCOL_NOTSUPPORT (PROTOCOL_BASE + 0x00000002) /*不支持*/
#define PROTOCOL_COMMFAIL (PROTOCOL_BASE + 0x00000003) /*通信错误*/
#define PROTOCOL_PARDENY (PROTOCOL_BASE + 0x00000007) /*UKey权限不满足*/
#define PROTOCOL_KEYNOTEXIST (PROTOCOL_BASE + 0x00000008) /*密钥不存在*/
#define PROTOCOL_ALGNOTSUPPORT (PROTOCOL_BASE + 0x00000009) /*不支持的算法*/
#define PROTOCOL_ALGMODNOTSUPPORT (PROTOCOL_BASE + 0x0000000A) /*不支持的算法模式*/
#define PROTOCOL_PKOPERR (PROTOCOL_BASE + 0x0000000B) /*公钥运算错误*/
#define PROTOCOL_SKOPERR (PROTOCOL_BASE + 0x0000000C) /*私钥运算错误*/
#define PROTOCOL_SIGNERR (PROTOCOL_BASE + 0x0000000D) /*签名错误*/
#define PROTOCOL_VERIFYERR (PROTOCOL_BASE + 0x0000000E) /*验证错误*/
#define PROTOCOL_SYMOPERR (PROTOCOL_BASE + 0x0000000F) /*对称运算错误*/
#define PROTOCOL_TOKENAUTHERR (PROTOCOL_BASE + 0x00000010) /*Token验证不通过*/
#define PROTOCOL_KEY_ALREADY_EXIST (PROTOCOL_BASE + 0x00000011) /*密钥不存在*/
#define PROTOCOL_TOKEN_NOT_EXITS (PROTOCOL_BASE + 0x00000012) /*Token没找到*/

/*KEK相关错误码定义*/
#define KEK_BASE 0x03000000
#define KEK_NO_UPDATE_AUTH (KEK_BASE + 0x00000001) /*无更新权限*/
#define KEK_NEED_PULL (KEK_BASE + 0x00000002) /*需要拉取KEK*/

/*DER编码相关错误码定义*/
#define DER_BASE 0x04000000
#define DER_FORMAT_ERR (DER_BASE + 0x00000001) /*DER编码错误*/

/*Netlink通讯相关错误码定义*/
#define NETLINK_BASE 0x05000000
#define NETLINK_SOCKET_CREATE_ERR (NETLINK_BASE + 0x00000001) /*Netlink打开串口失败*/
#define NETLINK_SOCKET_BIND_ERR (NETLINK_BASE + 0x00000002) /*Netlink打开串口失败*/
#define NETLINK_RECV_MSG_ERR (NETLINK_BASE + 0x00000003) /*Netlink接受消息失败*/

#ifdef __cplusplus
}
#endif

#endif  //CRYPTOCARDSDK_ERRNO_H
