package org.openeuler.sdf.commons.constant;

public interface SDFConstant {
    byte[] DEFAULT_ID = "1234567812345678".getBytes();

    // SM1/SM4/SM7/Hmac Encrypted key size
    int ENC_SYS_PRIVATE_KEY_SIZE = 1024;  // key size in bytes

    // SM2 Encrypted key size
    int ENC_SM2_PRIVATE_KEY_SIZE = 1024;  // key size in bytes

    int SM2_PUBLIC_KEY_X_LEN = 32;
    int SM2_PUBLIC_KEY_Y_LEN = 32;
}
