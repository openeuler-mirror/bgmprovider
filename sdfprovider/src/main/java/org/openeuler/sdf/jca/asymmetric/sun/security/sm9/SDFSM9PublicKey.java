package org.openeuler.sdf.jca.asymmetric.sun.security.sm9;

import java.security.PublicKey;

public class SDFSM9PublicKey implements PublicKey {
    private static final long serialVersionUID = -231226701277997668L;
    private final byte[] publicKey;
    private byte[] hId = SDFSM9KeyParam.DEFAULT_HID;
    private byte[] userId = SDFSM9KeyParam.DEFAULT_USERID;
    private byte[] pairG = null;
    private int encMode = SDFSM9KeyParam.DEFAULT_ENC_MODE;

    public SDFSM9PublicKey(byte[] publicKey, byte[] pairG, byte[] hId, byte[] userId, int encMode) {
        this.publicKey = publicKey.clone();
        this.pairG = pairG.clone();
        this.hId = hId.clone();
        this.userId = userId.clone();
        this.encMode = encMode;
    }

    public SDFSM9PublicKey(byte[] encoded) {
        this.publicKey = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return "SM9MasterKey";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return this.publicKey;
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
