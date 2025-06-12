package org.openeuler.sdf.jca.asymmetric.sun.security.sm9;

public class SDFSM9MasterPrivateKey extends SDFSM9PrivateKey {
    private static final long serialVersionUID = 95584473697207536L;

    public SDFSM9MasterPrivateKey(byte[] privateKey, byte[] pairG, byte[] hId, byte[] userId, int encMode) {
        super(privateKey, pairG, hId, userId, encMode);
    }

    public SDFSM9MasterPrivateKey(byte[] privateKey) {
        super(privateKey);
    }

    @Override
    public String getAlgorithm() {
        return "SM9MasterPrivateKey";
    }
}
