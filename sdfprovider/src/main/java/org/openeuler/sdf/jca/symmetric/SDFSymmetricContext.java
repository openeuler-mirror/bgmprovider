package org.openeuler.sdf.jca.symmetric;

import org.openeuler.sdf.commons.base.AbstractSDFHandle;

public class SDFSymmetricContext extends AbstractSDFHandle {
    public SDFSymmetricContext(long sessionAddress, long ctxAddress) {
        super(ctxAddress);
        setReference(new SDFSymmetricContextRef(this, sessionAddress, ctxAddress));
    }
}
