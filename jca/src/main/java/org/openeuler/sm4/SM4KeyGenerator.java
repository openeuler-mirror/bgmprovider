package org.openeuler.sm4;

import org.openeuler.BGMJCEProvider;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM4KeyGenerator extends KeyGeneratorSpi {
    private byte[] key;
    private int keySize = 16; // default keysize (in number of bytes)
    private SecureRandom random;

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException
                ("SM4 key generation does not take any parameters");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != 128) {
            throw new InvalidParameterException("SM4 requires a 128 bit key");
        }
        this.keySize = keysize / 8;
        engineInit(random);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        key = new byte[keySize];
        if (random == null) {
            random = BGMJCEProvider.getRandom();
        }
        random.nextBytes(key);
        return new SecretKeySpec(key, "SM4");
    }
}
