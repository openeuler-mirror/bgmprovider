package org.openeuler.sm4;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM4KeyGenerator extends KeyGeneratorSpi {
    private byte[] key;
    private int keySize;
    private SecureRandom random;

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.random=random;
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        this.random = random;
        this.keySize = keysize;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        key = new byte[keySize];
        if(random == null){
            random = new SecureRandom();
        }
        random.nextBytes(key);
        return new SecretKeySpec(key,"SM4");
    }
}
