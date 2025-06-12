/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

package org.openeuler.sdf.commons.constant;

public enum SDFDataKeyType {
    DATA_KEY_SM2("SM2",0),
    DATA_KEY_RSA("RSA",1),
    DATA_KEY_ECC("ECC",2),
    DATA_KEY_SM4("SM4",3),
    DATA_KEY_SM1("SM1",4),
    DATA_KEY_SM7("SM7",5),
    DATA_KEY_AES("AES",6),
    DATA_KEY_3DES("3DES",7),
    DATA_KEY_HMAC_SM3("HmacSM3",8),
    DATA_KEY_HMAC_SHA1("HmacSHA1",9),
    DATA_KEY_HMAC_SHA224("HmacSHA224",10),
    DATA_KEY_HMAC_SHA256("HmacSHA256",11),
    DATA_KEY_HMAC_SHA384("HmacSHA384",12),
    DATA_KEY_HMAC_SHA512("HmacSHA512",13),
    DATA_KEY_SM9_MASTER_SIGN("SM9MasterSign",14),
    DATA_KEY_SM9_MASTER_ENC("SM9MasterEnc",15),
    DATA_KEY_SM9_USER_SIGN("SM9UserSign",16),
    DATA_KEY_SM9_USER_ENC("SM9UserEnc",17);
    final String algorithm;
    final int type;

    SDFDataKeyType(String algorithm, int type) {
        this.algorithm = algorithm;
        this.type = type;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getType() {
        return type;
    }
}
