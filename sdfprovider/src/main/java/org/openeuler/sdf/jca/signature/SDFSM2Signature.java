package org.openeuler.sdf.jca.signature;

import org.openeuler.org.bouncycastle.SM2ParameterSpec;
import org.openeuler.sdf.commons.constant.SDFConstant;
import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.commons.key.SDFEncryptKey;
import org.openeuler.sdf.jca.asymmetric.sun.security.ec.SDFECKeyFactory;
import org.openeuler.sdf.jca.commons.SDFUtil;
import org.openeuler.sdf.wrapper.SDFSM2KeyPairGeneratorNative;
import org.openeuler.sdf.wrapper.SDFSM2SignatureNative;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ECUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class SDFSM2Signature extends SignatureSpi {

    // message digest implementation we use
    private final MessageDigest digest;

    // private key, if initialized for signing
    private ECPrivateKey privateKey;

    // public key, if initialized for verifying
    private ECPublicKey publicKey;

    // signature parameters
    private SM2ParameterSpec sigParams;

    private int curveBitLen;

    // use enc private key
    boolean isEncKey = false;

    public SDFSM2Signature(MessageDigest digest) {
        this.digest = digest;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.publicKey = (ECPublicKey) SDFECKeyFactory.toECKey(publicKey);
        this.curveBitLen = this.publicKey.getParams().getCurve().getField().getFieldSize();
        ECParameterSpec ecParams = this.publicKey.getParams();
        if (!isCompatible(this.sigParams, ecParams)) {
            throw new InvalidKeyException("Key params does not match signature params");
        }
        ECPoint pubPoint = this.publicKey.getW();
        byte[] z = getZ(ecParams, pubPoint);
        this.digest.reset();
        this.digest.update(z);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.privateKey = (ECPrivateKey) SDFECKeyFactory.toECKey(privateKey);
        this.curveBitLen = this.privateKey.getParams().getCurve().getField().getFieldSize();
        if (privateKey instanceof SDFEncryptKey) {
            this.isEncKey = ((SDFEncryptKey) privateKey).isEncKey();
        }
        ECParameterSpec ecParams = this.privateKey.getParams();
        if (!isCompatible(this.sigParams, ecParams)) {
            throw new InvalidKeyException("Key params does not match signature params");
        }
        ECPoint pubPoint = getPubECPoint();
        byte[] z = getZ(ecParams, pubPoint);
        this.digest.reset();
        this.digest.update(z);
    }

    @Override
    protected void engineUpdate(byte b) {
        this.digest.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        this.digest.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        byte[] uiCipherPriKey = SDFUtil.getPrivateKeyBytes(this.privateKey);
        byte[][] signatureParams;
        try {
            byte[] digestBytes = this.digest.digest();
            signatureParams = SDFSM2SignatureNative.nativeSM2Sign(
                    uiCipherPriKey, digestBytes);
        } finally {
            this.digest.reset();
        }
        return encodeSignature(signatureParams);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        boolean verify;
        try {
            int curveLen = getCurveLen();
            byte[] digestBytes = this.digest.digest();
            byte[] xArr = SDFUtil.asUnsignedByteArray(curveLen, this.publicKey.getW().getAffineX());
            byte[] yArr = SDFUtil.asUnsignedByteArray(curveLen, this.publicKey.getW().getAffineY());
            byte[][] signatureParams = decodeSignature(this.publicKey.getParams(), sigBytes);
            Object[] pubKeyArr = {
                    xArr, yArr
            };
            verify = SDFSM2SignatureNative.nativeSM2Verify(pubKeyArr, digestBytes, signatureParams);
        } catch (Exception e) {
            throw new SignatureException(e);
        } finally {
            this.digest.reset();
        }
        return verify;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (!(params instanceof SM2ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("only SM2ParameterSpec supported");
        }

        this.sigParams = (SM2ParameterSpec) params;
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (this.sigParams == null || this.sigParams.getParams() == null) {
            return null;
        }
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(this.sigParams.getParams());
            return ap;
        } catch (Exception e) {
            // should never happen
            throw new ProviderException("Error retrieving EC parameters", e);
        }
    }

    private ECPoint getPubECPoint() {
        ECPoint pubPoint;

        byte[][] keys;
        try {
            keys = SDFSM2KeyPairGeneratorNative.nativeGeneratePublicKey(SDFUtil.getPrivateKeyBytes(this.privateKey));
        } catch (Exception e) {
            throw new SDFRuntimeException("SDFSM2Signature failed. unable to generate PublicKey", e);
        }

        /*
         * typedef enum SDF_ECKeyIndex {
         *     SDF_EC_PBK_X_IDX = 0,
         *     SDF_EC_PBK_Y_IDX = 1,
         *     SDF_EC_PRK_S_IDX = 2
         * } SDF_ECKeyIndex;
         */
        BigInteger wX = new BigInteger(1, keys[0]);
        BigInteger wY = new BigInteger(1, keys[1]);
        pubPoint = new ECPoint(wX, wY);

        return pubPoint;
    }

    private byte[] getId() {
        if (this.sigParams == null || this.sigParams.getId() == null) {
            // default value
            return SDFConstant.DEFAULT_ID;
        }

        byte[] id = this.sigParams.getId();
        if (id.length >= 8192) {
            throw new IllegalArgumentException("SM2 user ID must be less than 2^16 bits long");
        }
        return id;
    }

    private int getCurveLen() {
        return (this.curveBitLen + 7) >> 3;
    }

    private byte[] getZ(ECParameterSpec ecParams, ECPoint pubPoint) {
        byte[] id = getId();
        byte[] entLen = new byte[2];
        entLen[0] = (byte) (((id.length * 8) >> 8) & 0xFF);
        entLen[1] = (byte) ((id.length * 8) & 0xFF);

        int curveLen = getCurveLen();
        this.digest.reset();
        // Z = H(entLen || ID || a || b || xG || yG || xA || yA)
        this.digest.update(entLen);
        this.digest.update(id);
        this.digest.update(SDFUtil.asUnsignedByteArray(curveLen, ecParams.getCurve().getA()));
        this.digest.update(SDFUtil.asUnsignedByteArray(curveLen, ecParams.getCurve().getB()));
        this.digest.update(SDFUtil.asUnsignedByteArray(curveLen, ecParams.getGenerator().getAffineX()));
        this.digest.update(SDFUtil.asUnsignedByteArray(curveLen, ecParams.getGenerator().getAffineY()));
        this.digest.update(SDFUtil.asUnsignedByteArray(curveLen, pubPoint.getAffineX()));
        this.digest.update(SDFUtil.asUnsignedByteArray(curveLen, pubPoint.getAffineY()));

        return this.digest.digest();
    }

    private static boolean isCompatible(SM2ParameterSpec sigParams,
                                        ECParameterSpec keyParams) {
        if (sigParams == null || sigParams.getParams() == null) {
            // no restriction on key param
            return true;
        }
        return ECUtil.equals(sigParams.getParams(), keyParams);
    }

    private byte[] encodeSignature(byte[][] params) throws SignatureException {
        byte[] signBytes;
        DerOutputStream out = new DerOutputStream();
        try {
            out.putInteger(new BigInteger(1, params[0]));
            out.putInteger(new BigInteger(1, params[1]));
            DerValue result = new DerValue(DerValue.tag_Sequence, out.toByteArray());
            signBytes = result.toByteArray();
        } catch (IOException e) {
            throw new SignatureException(e);
        }
        return signBytes;
    }

    // Convert the DER encoding of R and S into a concatenation of R and S
    private byte[][] decodeSignature(ECParameterSpec ecParams, byte[] sigBytes) throws SignatureException {
        BigInteger n = ecParams.getOrder();
        int curveLen = (ecParams.getCurve().getField().getFieldSize() + 7) / 8;
        try {
            // Enforce strict DER checking for signatures
            DerInputStream in = new DerInputStream(sigBytes, 0, sigBytes.length, false);
            DerValue[] values = in.getSequence(2);

            // check number of components in the read sequence
            // and trailing data
            if ((values.length != 2) || (in.available() != 0)) {
                throw new IOException("Invalid encoding for signature");
            }

            BigInteger r = values[0].getPositiveBigInteger();
            if (r.signum() < 0 || (null != n && r.compareTo(n) >= 0)) {
                throw new IllegalArgumentException("Value out of range");
            }

            BigInteger s = values[1].getPositiveBigInteger();
            if (s.signum() < 0 || (null != n && s.compareTo(n) >= 0)) {
                throw new IllegalArgumentException("Value out of range");
            }
            return new byte[][]{
                    SDFUtil.asUnsignedByteArray(curveLen, r),
                    SDFUtil.asUnsignedByteArray(curveLen, s),
            };
        } catch (IOException e) {
            throw new SignatureException("Invalid encoding for signature", e);
        }
    }

    static public class SDFSM3WithSM2
            extends SDFSM2Signature {
        public SDFSM3WithSM2() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SM3"));
        }
    }
}
