package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.spec.SDFEncKeyGenParameterSpec;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9KeyParam;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SDFSM9ParameterSpec implements SDFEncKeyGenParameterSpec {
    private final SDFKEKInfoEntity kekInfo;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private byte[] hId = SDFSM9KeyParam.DEFAULT_HID;
    private byte[] userId = SDFSM9KeyParam.DEFAULT_USERID;
    // enc mode: 0-key, 1-SM4_ecb_enc_pkcs#5
    private int encMode = SDFSM9KeyParam.DEFAULT_ENC_MODE;

    public SDFSM9ParameterSpec(SDFKEKInfoEntity kekInfo, KeyPair keyPair, byte[] hId, byte[] userId, int encMode) {
        this.kekInfo = kekInfo;
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        this.hId = hId.clone();
        this.userId = userId.clone();
        this.encMode = encMode;
    }

    public SDFSM9ParameterSpec(SDFKEKInfoEntity kekInfo, KeyPair keyPair) {
        this.kekInfo = kekInfo;
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public SDFSM9ParameterSpec(SDFKEKInfoEntity kekInfo, byte[] hId, byte[] userId, int encMode) {
        this.kekInfo = kekInfo;
        this.hId = hId.clone();
        this.userId = userId.clone();
        this.encMode = encMode;
    }

    @Override
    public SDFKEKInfoEntity getKekInfo() {
        return this.kekInfo;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
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
