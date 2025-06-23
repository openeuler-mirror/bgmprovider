/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Huawei designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Huawei in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please visit https://gitee.com/openeuler/bgmprovider if you need additional
 * information or have any questions.
 */

package org.openeuler;

import org.openeuler.adaptor.DerOutputStreamAdapter;
import org.openeuler.adaptor.ObjectIdentifierHandler;
import org.openeuler.constant.GMConstants;
import org.openeuler.org.bouncycastle.SM2ParameterSpec;
import org.openeuler.sun.security.ec.ECKeyFactory;
import org.openeuler.util.GMUtil;
import org.openeuler.util.Util;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ECUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class SM2Signature extends SignatureSpi {

    // message digest implementation we use
    private final MessageDigest digest;

    // private key, if initialized for signing
    private ECPrivateKey privateKey;

    // public key, if initialized for verifying
    private ECPublicKey publicKey;

    // signature parameters
    private SM2ParameterSpec sigParams;

    private ECPoint pubPoint;

    SM2Signature(String algorithm) {
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
    }


    /**
     * Initializes this signature object with the specified
     * public key for verification operations.
     *
     * @param publicKey the public key of the identity whose signature is
     *                  going to be verified.
     */
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        this.publicKey = (ECPublicKey) ECKeyFactory.toECKey(publicKey);
        if (!isCompatible(this.sigParams, this.publicKey.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        }
        this.pubPoint = ((ECPublicKey) publicKey).getW();
        ECParameterSpec ecParams = this.publicKey.getParams();

        initZ(ecParams);
    }

    /**
     * Initializes this signature object with the specified
     * private key for signing operations.
     *
     * @param privateKey the private key of the identity whose signature
     *                   will be generated.
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.privateKey = (ECPrivateKey) ECKeyFactory.toECKey(privateKey);
        if (!isCompatible(this.sigParams, this.privateKey.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        }
        ECParameterSpec ecParams = this.privateKey.getParams();
        this.pubPoint = GMUtil.multiply(ecParams.getGenerator(), this.privateKey.getS(), ecParams.getCurve());

        initZ(ecParams);
    }

    /**
     * Updates the data to be signed or verified
     * using the specified byte.
     *
     * @param b the byte to use for the update.
     * @throws SignatureException if the engine is not initialized
     *                            properly.
     */
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        digest.update(b);
    }

    /**
     * Updates the data to be signed or verified, using the
     * specified array of bytes, starting at the specified offset.
     *
     * @param b   the array of bytes
     * @param off the offset to start from in the array of bytes
     * @param len the number of bytes to use, starting at offset
     * @throws SignatureException if the engine is not initialized
     *                            properly
     */
    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        digest.update(b, off, len);
    }

    /**
     * Returns the signature bytes of all the data
     * updated so far.
     * The format of the signature depends on the underlying
     * signature scheme.
     *
     * @return the signature bytes of the signing operation's result.
     * @throws SignatureException if the engine is not
     *                            initialized properly or if this signature algorithm is unable to
     *                            process the input data provided.
     */
    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            byte[] eHash = digest.digest();
            //  e = H(Z || M)
            BigInteger e = new BigInteger(1, eHash);

            ECParameterSpec ecParams = this.privateKey.getParams();
            BigInteger n = ecParams.getOrder();
            BigInteger d = privateKey.getS();

            BigInteger r, s, k;

            do {
                do {
                    do {
                        // 1 <= k <= n-1
                        int nBitLen = n.bitLength();
                        k = Util.createRandomBigInteger(nBitLen, appRandom);
                    }
                    while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(n) >= 0);

                    // (x1, y1) = [k]G
                    BigInteger x1 = GMUtil.multiply(ecParams.getGenerator(), k, ecParams.getCurve()).getAffineX();

                    // r = (e + x1) mod n
                    r = e.add(x1).mod(n);
                }
                while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));

                // S = ((1 + d)^(-1) * (k - r * d)) mod n
                s = d.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(d).mod(n)).mod(n)).mod(n);
            }
            while (s.equals(BigInteger.ZERO));
            return encodeSignature(r, s);
        } catch (Exception e) {
            throw new SignatureException("unable to create signature: " + e.getMessage());
        }
    }

    /**
     * Verifies the passed-in signature.
     *
     * @param sigBytes the signature bytes to be verified.
     * @return true if the signature was verified, false if not.
     * @throws SignatureException if the engine is not
     *                            initialized properly, the passed-in signature is improperly
     *                            encoded or of the wrong type, if this signature algorithm is unable to
     *                            process the input data provided, etc.
     */
    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            ECParameterSpec ecParams = this.publicKey.getParams();
            BigInteger n = ecParams.getOrder();
            BigInteger[] rs = decodeSignature(n, sigBytes);

            BigInteger r = rs[0], s = rs[1];

            // Require: 0 < r < n
            if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(n) >= 0) {
                return false;
            }

            // Require: 0 < s < n
            if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(n) >= 0) {
                return false;
            }

            byte[] eHash = digest.digest();
            // e = H(Z || m)
            BigInteger e = new BigInteger(1, eHash);

            // t = (r + s) mod n
            BigInteger t = r.add(s).mod(n);
            // Require: t != 0
            if (t.equals(BigInteger.ZERO)) {
                return false;
            }

            // (x1, y1) = [s]G + [t]P
            ECPoint x1y1 = GMUtil.add(GMUtil.multiply(ecParams.getGenerator(), s, ecParams.getCurve()),
                    GMUtil.multiply(pubPoint, t, ecParams.getCurve()));
            if (x1y1.equals(ECPoint.POINT_INFINITY)) {
                return false;
            }

            // R = (e + x1) mod n
            BigInteger R = e.add(x1y1.getAffineX()).mod(n);

            return R.equals(r);
        } catch (Exception e) {
            throw new SignatureException(e.getMessage());
        }
    }

    // set parameter, not supported. See JCA doc
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof SM2ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("only SM2ParameterSpec supported");
        }

        sigParams = (SM2ParameterSpec) params;
    }

    // get parameter, not supported. See JCA doc
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (sigParams == null || sigParams.getParams() == null) {
            return null;
        }
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(sigParams.getParams());
            return ap;
        } catch (Exception e) {
            // should never happen
            throw new ProviderException("Error retrieving EC parameters", e);
        }
    }

    // id
    private byte[] getId() {
        if (this.appRandom == null) {
            this.appRandom = new SecureRandom();
        }

        byte[] id;
        if (sigParams == null || sigParams.getId() == null) {
            // default value
            id = GMConstants.DEFAULT_ID;
        } else {
            id = sigParams.getId();
            if (id.length >= 8192) {
                throw new IllegalArgumentException("SM2 user ID must be less than 2^16 bits long");
            }
        }
        return id;
    }

    // entLen
    private byte[] getEntLen() {
        byte[] ID = getId();
        byte[] entLen = new byte[2];
        entLen[0] = (byte) (((ID.length * 8) >> 8) & 0xFF);
        entLen[1] = (byte) ((ID.length * 8) & 0xFF);
        return entLen;
    }

    // Z = H(entLen || id || a || b || xG || yG || xA || yA)
    private byte[] getZ(ECParameterSpec ecParams) {
        byte[] entLen = getEntLen();
        byte[] id = getId();
        int curveLen = (ecParams.getCurve().getField().getFieldSize() + 7) / 8;

        digest.update(entLen);
        digest.update(id);
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getCurve().getA()));
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getCurve().getB()));
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getGenerator().getAffineX()));
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getGenerator().getAffineY()));
        digest.update(Util.asUnsignedByteArray(curveLen, pubPoint.getAffineX()));
        digest.update(Util.asUnsignedByteArray(curveLen, pubPoint.getAffineY()));
        return digest.digest();
    }

    private void initZ(ECParameterSpec ecParams) {
        // compute Z
        digest.reset();
        byte[] z = getZ(ecParams);

        // update Z
        digest.reset();
        digest.update(z);
    }

    private byte[] encodeSignature(BigInteger r, BigInteger s) throws IOException {
        DerOutputStream out = new DerOutputStream();
        DerOutputStreamAdapter outAdapter = new DerOutputStreamAdapter(out);
        outAdapter.putInteger(r);
        outAdapter.putInteger(s);
        DerValue result = new DerValue(DerValue.tag_Sequence, out.toByteArray());

        return result.toByteArray();
    }

    // Convert the DER encoding of R and S into a concatenation of R and S
    private BigInteger[] decodeSignature(BigInteger n, byte[] sig) throws SignatureException {

        try {
            // Enforce strict DER checking for signatures
            DerInputStream in = new DerInputStream(sig, 0, sig.length, false);
            DerValue[] values = in.getSequence(2);

            // check number of components in the read sequence
            // and trailing data
            if ((values.length != 2) || (in.available() != 0)) {
                throw new IOException("Invalid encoding for signature");
            }

            BigInteger r = values[0].getPositiveBigInteger();
            BigInteger s = values[1].getPositiveBigInteger();

            if (r.signum() < 0 || (null != n && r.compareTo(n) >= 0)) {
                throw new IllegalArgumentException("Value out of range");
            }
            if (s.signum() < 0 || (null != n && s.compareTo(n) >= 0)) {
                throw new IllegalArgumentException("Value out of range");
            }

            return new BigInteger[]{r, s};

        } catch (Exception e) {
            throw new SignatureException("Invalid encoding for signature", e);
        }
    }

    private static boolean isCompatible(SM2ParameterSpec sigParams,
                                        ECParameterSpec keyParams) {
        if (sigParams == null || sigParams.getParams() == null) {
            // no restriction on key param
            return true;
        }
        return ECUtil.equals(sigParams.getParams(), keyParams);
    }

    // Nested class for SM3withSM2 signatures
    public static final class SM3withSM2 extends SM2Signature {
        public SM3withSM2() throws NoSuchAlgorithmException {
            super("SM3");
        }
    }
}
