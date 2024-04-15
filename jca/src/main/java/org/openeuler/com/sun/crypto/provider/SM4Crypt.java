package org.openeuler.com.sun.crypto.provider;


import org.openeuler.sm4.SM4Util;

import java.security.InvalidKeyException;

import static org.openeuler.com.sun.crypto.provider.SM4Constants.SM4_KEYSIZES;

public class SM4Crypt extends SymmetricCipher {
    private SM4Util sm4Util;
    private int[] rk;
    @Override
    int getBlockSize() {
        return SM4Constants.SM4_BLOCK_SIZE;
    }

    @Override
    void init(boolean decrypting, String algorithm, byte[] key) throws InvalidKeyException {
        sm4Util = new SM4Util();
        rk = sm4Util.expandKey(key);
    }

    @Override
    void encryptBlock(byte[] plain, int plainOffset, byte[] cipher, int cipherOffset) {
        sm4Util.encrypt(rk, plain, plainOffset, cipher, cipherOffset);
    }

    @Override
    void decryptBlock(byte[] cipher, int cipherOffset, byte[] plain, int plainOffset) {
        sm4Util.decrypt(rk, cipher, cipherOffset, plain, plainOffset);
    }

    // check if the specified length (in bytes) is a valid keysize for SM4
    static final boolean isKeySizeValid(int len) {
        for (int i = 0; i < SM4_KEYSIZES.length; i++) {
            if (len == SM4_KEYSIZES[i]) {
                return true;
            }
        }
        return false;
    }
}
