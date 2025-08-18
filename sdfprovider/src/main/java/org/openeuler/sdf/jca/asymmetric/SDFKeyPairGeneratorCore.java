package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.spec.SDFEncKeyGenParameterSpec;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;

import javax.naming.OperationNotSupportedException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

abstract class SDFKeyPairGeneratorCore extends KeyPairGeneratorSpi {
    // current key size in bits
    protected int keySize;
    protected SDFKEKInfoEntity kekInfo;

    SDFKeyPairGeneratorCore(int defaultKeySize) {
        initialize(defaultKeySize, null);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        checkKeySize(keysize);
        this.keySize = keysize;
        this.kekInfo = SDFKEKInfoEntity.getDefaultKEKInfo();
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        checkParameterSpec(params);
        if (params instanceof SDFEncKeyGenParameterSpec) {
            this.kekInfo = ((SDFEncKeyGenParameterSpec) params).getKekInfo();
        }
        if (this.kekInfo == null) {
            this.kekInfo = SDFKEKInfoEntity.getDefaultKEKInfo();
        }
    }

    protected abstract void checkKeySize(int keysize) throws InvalidParameterException;

    protected abstract void checkParameterSpec(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException;

    protected boolean isEncKey() {
        return kekInfo != null;
    }


    protected byte[][] implGenerateKeyPair() {
        if (this.kekInfo == null) {
            throw new IllegalArgumentException("Not support generate sm2 plain key");
        }
        byte[][] keys;
        try {
            keys = implGenerateKeyPair(kekInfo, keySize);
        } catch (SDFException e) {
            throw new RuntimeException(e);
        }
        return keys;
    }

    protected abstract byte[][] implGenerateKeyPair(SDFKEKInfoEntity kekInfo, int keySize)
            throws SDFException;
}
