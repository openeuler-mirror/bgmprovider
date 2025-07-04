package org.openeuler.sdf.jca.asymmetric.sun.security.sm9;

import java.security.PrivateKey;

public abstract class SDFSM9PrivateKey implements PrivateKey {
    private static final long serialVersionUID = 8403772873710770109L;
    private final byte[] privateKey;
    private byte[] hId = SDFSM9KeyParam.DEFAULT_HID;
    private byte[] userId = SDFSM9KeyParam.DEFAULT_USERID;
    private byte[] pairG = null;
    private int encMode = SDFSM9KeyParam.DEFAULT_ENC_MODE;

    public SDFSM9PrivateKey(byte[] privateKey, byte[] pairG, byte[] hId, byte[] userId, int encMode) {
        this.privateKey = privateKey.clone();
        this.pairG = pairG.clone();
        this.hId = hId.clone();
        this.userId = userId.clone();
        this.encMode = encMode;
    }

    public SDFSM9PrivateKey(byte[] encoded) {
        this.privateKey = encoded.clone();
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return privateKey;
    }

    public byte[] getPairG() {
        return pairG;
    }

    public byte[] getHId() {
        return hId;
    }

    public byte[] getUserId() {
        return userId;
    }

    public int getEncMode() {
        return encMode;
    }
}
