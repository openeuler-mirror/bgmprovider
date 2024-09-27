package org.openeuler.sdf.commons.base;

public class SDFExampleRef extends AbstractSDFRef<SDFExampleHandle> {
    protected SDFExampleRef(SDFExampleHandle reference) {
        super(reference, reference.getAddress());
    }

    @Override
    protected void free(long address) {

    }
}
