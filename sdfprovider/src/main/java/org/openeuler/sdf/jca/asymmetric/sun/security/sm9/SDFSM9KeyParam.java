package org.openeuler.sdf.jca.asymmetric.sun.security.sm9;

public interface SDFSM9KeyParam {
    byte[] DEFAULT_HID = new byte[] {3};
    byte[] DEFAULT_USERID = "SDF_SM9_DEFAULT_USER".getBytes();
    int DEFAULT_ENC_MODE = SM9EncMode.NORMAL.encMode;

    enum SM9EncMode {
        NORMAL(0),
        SM4_ECB_ENC_PKCS5(1);

        final int encMode;
        SM9EncMode(int encMode) {
            this.encMode = encMode;
        }
    }
}
