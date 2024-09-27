package org.openeuler.sdf.commons.device;

import org.openeuler.sdf.commons.base.AbstractSDFHandle;

public class SDFDevice extends AbstractSDFHandle {
    public SDFDevice(long address) {
        super(address);
        setReference(new SDFDeviceRef(this));
    }
}
