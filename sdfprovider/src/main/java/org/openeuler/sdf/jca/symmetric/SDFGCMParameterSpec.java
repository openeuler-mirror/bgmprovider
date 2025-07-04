package org.openeuler.sdf.jca.symmetric;

import javax.crypto.spec.GCMParameterSpec;

public class SDFGCMParameterSpec extends GCMParameterSpec {
    private byte[] tag;

    public SDFGCMParameterSpec(int tLen, byte[] src) {
        super(tLen, src);
        this.tag = new byte[16];
    }

    public byte[] getTag() {
        return tag;
    }

    public void setTag(byte[] tag) {
        this.tag = tag;
    }
}
