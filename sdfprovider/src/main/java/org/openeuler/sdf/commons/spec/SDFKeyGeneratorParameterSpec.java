package org.openeuler.sdf.commons.spec;

import java.security.spec.AlgorithmParameterSpec;

public class SDFKeyGeneratorParameterSpec implements AlgorithmParameterSpec {
    private final SDFKEKInfoEntity kekInfo;
    private final int keySize;

    public SDFKeyGeneratorParameterSpec(SDFKEKInfoEntity kekInfo, int keySize) {
        this.kekInfo = kekInfo;
        this.keySize = keySize;
    }

    public SDFKeyGeneratorParameterSpec(byte[] kekId, byte[] regionId, byte[] cdpId, byte[] PIN, int keySize) {
        this(new SDFKEKInfoEntity(kekId, regionId, cdpId, PIN), keySize);
    }

    public int getKeySize() {
        return keySize;
    }

    public SDFKEKInfoEntity getKekInfo() {
        return kekInfo;
    }
}
