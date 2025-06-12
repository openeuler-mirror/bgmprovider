package org.openeuler.sdf.jca.signature;

import org.openeuler.sdf.jca.asymmetric.SDFSM9ParameterSpec;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9PublicKey;
import org.openeuler.sdf.jca.asymmetric.sun.security.sm9.SDFSM9UserPrivateKey;
import org.openeuler.sdf.wrapper.SDFSM9SignatureNative;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SDFSM9Signature extends SignatureSpi {
    private final ByteArrayOutputStream byteBuf = new ByteArrayOutputStream();
    private SDFSM9PublicKey publicKey;
    private SDFSM9UserPrivateKey privateKey;
    private SDFSM9ParameterSpec spec;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof SDFSM9PublicKey) {
            this.publicKey = (SDFSM9PublicKey) publicKey;
        }
        byteBuf.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof SDFSM9UserPrivateKey) {
            this.privateKey = (SDFSM9UserPrivateKey) privateKey;
        }
        byteBuf.reset();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byteBuf.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        byteBuf.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (publicKey == null || privateKey == null) {
            throw new SignatureException("PublicKey or privateKey cannot be null of signature");
        }
        byte[] signData = byteBuf.toByteArray();
        try {
            return SDFSM9SignatureNative.nativeSM9Sign(publicKey.getEncoded(), privateKey.getEncoded(),
                    signData, publicKey.getPairG());
        } finally {
            byteBuf.reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("PublicKey cannot be null of signature verify");
        }
        byte[] verifyData = byteBuf.toByteArray();
        try {
            return SDFSM9SignatureNative.nativeSM9Verify(publicKey.getEncoded(), sigBytes, verifyData,
                    publicKey.getPairG(), publicKey.getHId(), publicKey.getUserId());
        } finally {
            byteBuf.reset();
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params instanceof SDFSM9ParameterSpec) {
            this.spec = (SDFSM9ParameterSpec) params;
            this.publicKey = (SDFSM9PublicKey) spec.getPublicKey();
            this.privateKey = (SDFSM9UserPrivateKey) spec.getPrivateKey();
        } else {
            throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec must be SDFSM9ParameterSpec");
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return this.spec;
    }
}
