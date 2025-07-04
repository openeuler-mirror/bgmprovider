package org.openeuler.sdf.jca.symmetric;

import org.openeuler.sdf.commons.spec.SDFKeyGeneratorParameterSpec;

public class SDFXTSParameterSpec extends SDFKeyGeneratorParameterSpec {
    private final boolean isXts;

    public SDFXTSParameterSpec(byte[] kekId, byte[] regionId, byte[] cdpId, byte[] PIN, int keySize) {
        super(kekId, regionId, cdpId, PIN, keySize);
        this.isXts = true;
    }

    public boolean isXts() {
        return isXts;
    }
}
