package org.openeuler.sdf.commons.device;

import org.openeuler.sdf.wrapper.SDFDeviceNative;

public class SDFDeviceManager {
    private static final SDFDeviceManager instance = new SDFDeviceManager();
    public SDFDevice getDevice() {
        long address = SDFDeviceNative.nativeOpenDevice();
        return new SDFDevice(address);
    }

    public SDFDevice releaseDevice(SDFDevice device) {
        SDFDeviceNative.nativeCloseDevice(device.getAddress());
        return null;
    }

    public static SDFDeviceManager getInstance() {
        return instance;
    }
}
