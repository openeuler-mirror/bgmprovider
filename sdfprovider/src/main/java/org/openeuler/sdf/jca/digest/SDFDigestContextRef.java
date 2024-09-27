package org.openeuler.sdf.jca.digest;

import org.openeuler.sdf.commons.base.AbstractSDFRef;
import org.openeuler.sdf.wrapper.SDFDigestNative;


/**
 * SDF Digest Context Reference
 */
public class SDFDigestContextRef extends AbstractSDFRef<SDFDigestContext> {

    // Used when creating Digest Context
    private long sessionAddr;

    public SDFDigestContextRef(SDFDigestContext digest, long sessionAddr, long address) {
        super(digest, address);
        this.sessionAddr = sessionAddr;
    }

    @Override
    protected void free(long address) {
        try {
            SDFDigestNative.nativeDigestCtxFree(sessionAddr, address);
        } catch (Exception e) {
            throw new RuntimeException("DigestContextRef nativeDigestCtxFree failed ", e);
        }
    }
}
