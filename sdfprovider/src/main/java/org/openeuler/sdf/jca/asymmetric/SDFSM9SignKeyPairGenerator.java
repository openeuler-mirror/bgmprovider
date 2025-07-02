package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.constant.SDFDataKeyType;
import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.spec.SDFKEKInfoEntity;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9KeyParam;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9PublicKey;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9UserPrivateKey;
import org.openeuler.sdf.wrapper.SDFSM9KeyPairGeneratorNative;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SDFSM9SignKeyPairGenerator extends SDFKeyPairGeneratorCore {
    private SDFSM9ParameterSpec paramSpec = null;

    public SDFSM9SignKeyPairGenerator() {
        super(256);
    }

    @Override
    protected void checkKeySize(int keySize) throws InvalidParameterException {
        if (keySize != 256) {
            throw new InvalidParameterException("keySize must be 256");
        }
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        super.initialize(keySize, random);
        try {
            initialize(new SDFSM9ParameterSpec(SDFKEKInfoEntity.getDefaultKEKInfo(), SDFSM9KeyParam.DEFAULT_HID,
                    SDFSM9KeyParam.DEFAULT_USERID, SDFSM9KeyParam.DEFAULT_ENC_MODE), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        super.initialize(params, random);
    }

    @Override
    protected void checkParameterSpec(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params instanceof SDFSM9ParameterSpec) {
            paramSpec = (SDFSM9ParameterSpec) params;
        } else {
            throw new InvalidAlgorithmParameterException("SDFSM9ParameterSpec required for SM9 Sign");
        }
    }

    @Override
    protected byte[][] implGenerateKeyPair(SDFKEKInfoEntity kekInfo, int keySize) throws SDFException {
        return SDFSM9KeyPairGeneratorNative.nativeGenerateKeyPair(
                SDFDataKeyType.DATA_KEY_SM9_MASTER_SIGN.getType(),
                kekInfo.getKekId(),
                kekInfo.getRegionId(),
                kekInfo.getCdpId(),
                kekInfo.getPin()
        );
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[][] keys = implGenerateKeyPair();
        byte[] pairG = keys[2];
        PublicKey publicKey = new SDFSM9PublicKey(keys[0], pairG, paramSpec.getHId(),
                paramSpec.getUserId(), paramSpec.getEncMode());
        byte[] userPriKey = SDFSM9KeyPairGeneratorNative
                .nativeCreateUserPriKey(SDFDataKeyType.DATA_KEY_SM9_USER_SIGN.getType(),
                        keys[1], paramSpec.getHId(), paramSpec.getUserId());
        PrivateKey privateKey = new SDFSM9UserPrivateKey(userPriKey, pairG, paramSpec.getHId(),
                paramSpec.getUserId(), paramSpec.getEncMode());
        return new KeyPair(publicKey, privateKey);
    }
}
