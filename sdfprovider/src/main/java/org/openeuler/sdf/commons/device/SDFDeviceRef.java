package org.openeuler.sdf.commons.device;

import org.openeuler.sdf.commons.base.AbstractSDFRef;
import org.openeuler.sdf.wrapper.SDFDeviceNative;

public class SDFDeviceRef extends AbstractSDFRef<SDFDevice> {
    public SDFDeviceRef(SDFDevice device) {
        super(device, device.getAddress());
    }

    @Override
    protected void free(long address) {
        SDFDeviceNative.nativeCloseDevice(address);
    }
}
