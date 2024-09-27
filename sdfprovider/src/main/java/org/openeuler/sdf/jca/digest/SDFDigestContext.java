package org.openeuler.sdf.jca.digest;

import org.openeuler.sdf.commons.base.AbstractSDFHandle;

public class SDFDigestContext extends AbstractSDFHandle {
    public SDFDigestContext(long sessionAddress, long ctxAddress) {
        super(ctxAddress);
        setReference(new SDFDigestContextRef(this, sessionAddress, ctxAddress));
    }
}
