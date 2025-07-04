package org.openeuler.sdf.commons.util;

public class SDFTestCase {
    static {
        init();
    }
    static void init() {
        System.setProperty("sdf.sdkConfig", SDFTestUtil.getSdkConfig());
    }
}
