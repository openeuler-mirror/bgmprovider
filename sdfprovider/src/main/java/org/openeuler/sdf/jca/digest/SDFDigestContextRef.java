package org.openeuler.sdf.jca.digest;

import org.openeuler.sdf.commons.base.AbstractSDFRef;
import org.openeuler.sdf.wrapper.SDFDigestNative;


/**
 * SDF Digest Context Reference
 */
public class SDFDigestContextRef extends AbstractSDFRef<SDFDigestContext> {
    public SDFDigestContextRef(SDFDigestContext digest, long address) {
        super(digest, address);
    }

    @Override
    protected void free(long address) {
        try {
            SDFDigestNative.nativeDigestCtxFree(address);
        } catch (Exception e) {
            throw new RuntimeException("DigestContextRef nativeDigestCtxFree failed ", e);
        }
    }
}
