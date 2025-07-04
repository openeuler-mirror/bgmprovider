package org.openeuler.sdf.commons.base;

public class SDFExampleHandle extends AbstractSDFHandle {
    public SDFExampleHandle(long address) {
        super(address);
        setReference(new SDFExampleRef(this));
    }
}
