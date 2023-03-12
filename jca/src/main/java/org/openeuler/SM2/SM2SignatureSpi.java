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

package org.openeuler.SM2;

import org.openeuler.util.ECUtil;
import org.openeuler.util.Util;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class SM2SignatureSpi extends SignatureSpi {

    // message digest implementation we use
    private final MessageDigest digest;

    // private key, if initialized for signing
    private ECPrivateKey privateKey;

    // public key, if initialized for verifying
    private ECPublicKey publicKey;

    private ECParameterSpec ecParams;

    // signature parameters
    private SM2ParameterSpec sm2Params;

    private ECPoint pubPoint;

    public SM2SignatureSpi() throws NoSuchAlgorithmException {
        this(MessageDigest.getInstance("SM3"));
    }

    public SM2SignatureSpi(MessageDigest digest) {
        this.digest = digest;
    }


    /**
     * Initializes this signature object with the specified
     * public key for verification operations.
     *
     * @param publicKey the public key of the identity whose signature is
     *                  going to be verified.
     */
    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        this.publicKey = (ECPublicKey) publicKey;
        ecParams = this.publicKey.getParams();
        byte[] userID = getUserID();
        byte[] idLen = new byte[2];

        // id bit length
        idLen[0] = (byte) (((userID.length * 8) >> 8) & 0xFF);
        idLen[1] = (byte) ((userID.length * 8) & 0xFF);

        pubPoint = ((ECPublicKey) publicKey).getW();

        byte[] z = getZ(idLen, userID);
        digest.update(z);
    }

    /**
     * Initializes this signature object with the specified
     * private key for signing operations.
     *
     * @param privateKey the private key of the identity whose signature
     *                   will be generated.
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        this.privateKey = (ECPrivateKey) privateKey;
        ecParams = this.privateKey.getParams();
        byte[] userID = getUserID();
        byte[] idLen = new byte[2];

        // id bit length
        idLen[0] = (byte) (((userID.length * 8) >> 8) & 0xFF);
        idLen[1] = (byte) ((userID.length * 8) & 0xFF);

        pubPoint = ECUtil.multiply(ecParams.getGenerator(), ((ECPrivateKey) privateKey).getS(), ecParams.getCurve());

        byte[] z = getZ(idLen, userID);
        digest.update(z);
    }

    protected byte[] getUserID() {
        byte[] userID;

        if (this.appRandom == null) {
            this.appRandom = new SecureRandom();
        }

        if (sm2Params == null || sm2Params.getID() == null) {
            // default value
            userID = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        } else {
            userID = sm2Params.getID();
            if (userID.length >= 8192)
            {
                throw new IllegalArgumentException("SM2 user ID must be less than 2^16 bits long");
            }
        }
        return userID;
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
        try
        {
            byte[] eHash = digest.digest();

            // Do not truncate values greater than n
            BigInteger n = ecParams.getOrder();
            BigInteger e = new BigInteger(1, eHash);
            BigInteger d = privateKey.getS();

            BigInteger r, s;

            // 5.2.1 Draft RFC:  SM2 Public Key Algorithms
            do // generate s
            {
                BigInteger k;
                do // generate r
                {
                    // A3
                    k = nextK(n);

                    // A4
                    ECPoint p = ECUtil.multiply(ecParams.getGenerator(), k, ecParams.getCurve());

                    // A5
                    r = e.add(p.getAffineX()).mod(n);
                }
                while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));

                // A6
                BigInteger dPlus1ModN = d.add(BigInteger.ONE).modInverse(n);

                s = k.subtract(r.multiply(d)).mod(n);
                s = dPlus1ModN.multiply(s).mod(n);
            }
            while (s.equals(BigInteger.ZERO));

            // A7
            try
            {
                return encodeSignature(n, r, s);
            }
            catch (Exception ex)
            {
                throw new SignatureException("unable to encode signature: " + ex.getMessage(), ex);
            }
        }
        catch (SignatureException e)
        {
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
        try
        {
            BigInteger n = ecParams.getOrder();
//            BigInteger[] rs = encoding.decode(n, sigBytes);
            BigInteger[] rs = decodeSignature(n, sigBytes);

            BigInteger r = rs[0], s = rs[1];

            // 5.3.1 Draft RFC:  SM2 Public Key Algorithms
            // B1
            if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0)
            {
                return false;
            }

            // B2
            if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0)
            {
                return false;
            }

            // B3
            byte[] eHash = digest.digest();

            // B4
            // Do not truncate values greater than n
            BigInteger e = new BigInteger(1, eHash);

            // B5
            BigInteger t = r.add(s).mod(n);
            if (t.equals(BigInteger.ZERO))
            {
                return false;
            }

            // B6
            ECPoint x1y1 = ECUtil.add(ECUtil.multiply(ecParams.getGenerator(), s, ecParams.getCurve()),
                    ECUtil.multiply(pubPoint, t, ecParams.getCurve()),
                    ecParams.getCurve());
            if (x1y1.equals(ECPoint.POINT_INFINITY))
            {
                return false;
            }

            // B7
            BigInteger expectedR = e.add(x1y1.getAffineX()).mod(n);

            return expectedR.equals(r);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.getMessage());
//            return false;
        }
    }

    /**
     * Sets the specified algorithm parameter to the specified
     * value. This method supplies a general-purpose mechanism through
     * which it is possible to set the various parameters of this object.
     * A parameter may be any settable parameter for the algorithm, such as
     * a parameter size, or a source of random bits for signature generation
     * (if appropriate), or an indication of whether or not to perform
     * a specific but optional computation. A uniform algorithm-specific
     * naming scheme for each parameter is desirable but left unspecified
     * at this time.
     *
     * @param param the string identifier of the parameter.
     * @param value the parameter value.
     * @throws InvalidParameterException if {@code param} is an
     *                                   invalid parameter for this signature algorithm engine,
     *                                   the parameter is already set
     *                                   and cannot be set again, a security exception occurs, and so on.
     * @deprecated Replaced by {@link
     * #engineSetParameter(AlgorithmParameterSpec)
     * engineSetParameter}.
     */
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
        if (params != null && !(params instanceof SM2ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("only SM2ParameterSpec supported");
        }

        sm2Params = (SM2ParameterSpec) params;
    }

    /**
     * Gets the value of the specified algorithm parameter.
     * This method supplies a general-purpose mechanism through which it
     * is possible to get the various parameters of this object. A parameter
     * may be any settable parameter for the algorithm, such as a parameter
     * size, or  a source of random bits for signature generation (if
     * appropriate), or an indication of whether or not to perform a
     * specific but optional computation. A uniform algorithm-specific
     * naming scheme for each parameter is desirable but left unspecified
     * at this time.
     *
     * @param param the string name of the parameter.
     * @return the object that represents the parameter value, or {@code null} if
     * there is none.
     * @throws InvalidParameterException if {@code param} is an
     *                                   invalid parameter for this engine, or another exception occurs while
     *                                   trying to get this parameter.
     * @deprecated
     */
    // get parameter, not supported. See JCA doc
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (ecParams == null) {
            return null;
        }
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(ecParams);
            return ap;
        } catch (Exception e) {
            // should never happen
            throw new ProviderException("Error retrieving EC parameters", e);
        }
    }

    private byte[] getZ(byte[] idLen, byte[] userID)
    {
        digest.reset();

        digest.update(idLen);
        digest.update(userID);

        int curveLen = (ecParams.getCurve().getField().getFieldSize() + 7) / 8;
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getCurve().getA()));
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getCurve().getB()));
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getGenerator().getAffineX()));
        digest.update(Util.asUnsignedByteArray(curveLen, ecParams.getGenerator().getAffineY()));
        digest.update(Util.asUnsignedByteArray(curveLen, pubPoint.getAffineX()));
        digest.update(Util.asUnsignedByteArray(curveLen, pubPoint.getAffineY()));

        return digest.digest();
    }

    private BigInteger nextK(BigInteger n)
    {
        int qBitLength = n.bitLength();

        BigInteger k;
        do
        {
            k = Util.createRandomBigInteger(qBitLength, appRandom);
        }
        while (k.equals(BigInteger.ZERO) || k.compareTo(n) >= 0);

        return k;
    }

    static public class sm3WithSM2
            extends SM2SignatureSpi
    {
        public sm3WithSM2() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SM3"));
        }
    }

    private byte[] encodeSignature(BigInteger n, BigInteger r, BigInteger s) throws IOException {
        DerOutputStream out = new DerOutputStream((int) ((r.bitLength() + 7) / 8) + (s.bitLength() + 7) / 8 + 10);
        out.putInteger(r);
        out.putInteger(s);
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

            if (r.signum() < 0 || (null != n && r.compareTo(n) >= 0))
            {
                throw new IllegalArgumentException("Value out of range");
            }
            if (s.signum() < 0 || (null != n && s.compareTo(n) >= 0))
            {
                throw new IllegalArgumentException("Value out of range");
            }

            return new BigInteger[]{ r, s };

        } catch (Exception e) {
            throw new SignatureException("Invalid encoding for signature", e);
        }
    }
}
