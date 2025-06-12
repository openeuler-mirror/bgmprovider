package org.openeuler.sdf.jca.asymmetric.sun.security.sm9;

public class SDFSM9UserPrivateKey extends SDFSM9PrivateKey {
    private static final long serialVersionUID = 6402657788757398428L;

    public SDFSM9UserPrivateKey(byte[] privateKey, byte[] pairG, byte[] hId, byte[] userId, int encMode) {
        super(privateKey, pairG, hId, userId, encMode);
    }

    public SDFSM9UserPrivateKey(byte[] privateKey) {
        super(privateKey);
    }

    @Override
    public String getAlgorithm() {
        return "SM9UserPrivateKey";
    }
}
