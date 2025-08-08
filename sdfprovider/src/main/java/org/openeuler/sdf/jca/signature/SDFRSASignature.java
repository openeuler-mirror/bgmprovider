/*
 * Copyright (c) 2003, 2020, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.openeuler.sdf.jca.signature;

import java.io.IOException;
import java.nio.ByteBuffer;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openeuler.adaptor.DerOutputStreamAdapter;
import org.openeuler.sdf.jca.asymmetric.SDFRSACore;
import sun.security.rsa.RSACore;
import sun.security.rsa.RSAKeyFactory;
import sun.security.rsa.RSAPadding;
import sun.security.rsa.RSAUtil;
import sun.security.rsa.RSAUtil.KeyType;
import sun.security.util.*;
import sun.security.x509.AlgorithmId;

/**
 * PKCS#1 v1.5 RSA signatures with the various message digest algorithms.
 * This file contains an abstract base class with all the logic plus
 * a nested static class for each of the message digest algorithms
 * (see end of the file). We support MD2, MD5, SHA-1, SHA-224, SHA-256,
 * SHA-384, SHA-512, SHA-512/224, and SHA-512/256.
 *
 * @since   1.5
 * @author  Andreas Sterbenz
 */
public abstract class SDFRSASignature extends SignatureSpi {

    // we sign an ASN.1 SEQUENCE of AlgorithmId and digest
    // it has the form 30:xx:30:xx:[digestOID]:05:00:04:xx:[digest]
    // this means the encoded length is (8 + digestOID.length + digest.length)
    private static final int baseLength = 8;

    // object identifier for the message digest algorithm used
    private final ObjectIdentifier digestOID;

    // length of the encoded signature blob
    private final int encodedLength;

    // message digest implementation we use
    private final MessageDigest md;
    // flag indicating whether the digest is reset
    private boolean digestReset;

    // private key, if initialized for signing
    private RSAPrivateKey privateKey;
    // public key, if initialized for verifying
    private RSAPublicKey publicKey;

    // padding to use, set when the initSign/initVerify is called
    private RSAPadding padding;

    /**
     * Construct a new RSASignature. Used by subclasses.
     */
    SDFRSASignature(String algorithm, ObjectIdentifier digestOID, int oidLength) {
        this.digestOID = digestOID;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
        digestReset = true;
        encodedLength = baseLength + oidLength + md.getDigestLength();
    }

    // initialize for verification. See JCA doc
    @Override
    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        RSAPublicKey rsaKey = (RSAPublicKey) RSAKeyFactory.toRSAKey(publicKey);
        this.privateKey = null;
        this.publicKey = rsaKey;
        initCommon(rsaKey, null);
    }

    // initialize for signing. See JCA doc
    @Override
    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    // initialize for signing. See JCA doc
    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        RSAPrivateKey rsaKey =
            (RSAPrivateKey)RSAKeyFactory.toRSAKey(privateKey);
        this.privateKey = rsaKey;
        this.publicKey = null;
        initCommon(rsaKey, random);
    }

    /**
     * Init code common to sign and verify.
     */
    private void initCommon(RSAKey rsaKey, SecureRandom random)
            throws InvalidKeyException {
        try {
            RSAUtil.checkParamsAgainstType(KeyType.RSA, rsaKey.getParams());
        } catch (ProviderException e) {
            throw new InvalidKeyException("Invalid key for RSA signatures", e);
        }
        resetDigest();
        int keySize = RSACore.getByteLength(rsaKey);
        try {
            padding = RSAPadding.getInstance
                (RSAPadding.PAD_BLOCKTYPE_1, keySize, random);
        } catch (InvalidAlgorithmParameterException iape) {
            throw new InvalidKeyException(iape.getMessage());
        }
        int maxDataSize = padding.getMaxDataSize();
        if (encodedLength > maxDataSize) {
            throw new InvalidKeyException
                ("Key is too short for this signature algorithm");
        }
    }

    /**
     * Reset the message digest if it is not already reset.
     */
    private void resetDigest() {
        if (digestReset == false) {
            md.reset();
            digestReset = true;
        }
    }

    /**
     * Return the message digest value.
     */
    private byte[] getDigestValue() {
        digestReset = true;
        return md.digest();
    }

    // update the signature with the plaintext data. See JCA doc
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        md.update(b);
        digestReset = false;
    }

    // update the signature with the plaintext data. See JCA doc
    @Override
    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        md.update(b, off, len);
        digestReset = false;
    }

    // update the signature with the plaintext data. See JCA doc
    @Override
    protected void engineUpdate(ByteBuffer b) {
        md.update(b);
        digestReset = false;
    }

    // sign the data and return the signature. See JCA doc
    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Missing private key");
        }
        byte[] digest = getDigestValue();
        try {
            byte[] encoded = encodeSignature(digestOID, digest);
            byte[] padded = padding.pad(encoded);
            byte[] encrypted = SDFRSACore.rsa(padded, privateKey);
            return encrypted;
        } catch (Exception e) {
            throw new SignatureException("Could not encode data", e);
        }
    }

    // verify the data and return the result. See JCA doc
    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("Missing public key");
        }

        if (sigBytes.length != RSACore.getByteLength(publicKey)) {
            throw new SignatureException("Signature length not correct: got " +
                    sigBytes.length + " but was expecting " +
                    RSACore.getByteLength(publicKey));
        }
        byte[] digest = getDigestValue();
        try {
            byte[] decrypted = SDFRSACore.rsa(sigBytes, publicKey);
            byte[] unpadded = padding.unpad(decrypted);
            byte[] decodedDigest = decodeSignature(digestOID, unpadded);
            return MessageDigest.isEqual(digest, decodedDigest);
        } catch (Exception e) {
            throw new SignatureException("Signature encoding error", e);
        }
    }

    /**
     * Encode the digest, return the to-be-signed data.
     * Also used by the PKCS#11 provider.
     */
    public static byte[] encodeSignature(ObjectIdentifier oid, byte[] digest)
            throws IOException {
        DerOutputStream out = new DerOutputStream();
        DerOutputStreamAdapter outAdapter = new DerOutputStreamAdapter(out);
        new AlgorithmId(oid).encode(out);
        outAdapter.putOctetString(digest);
        DerValue result =
            new DerValue(DerValue.tag_Sequence, out.toByteArray());
        return result.toByteArray();
    }

    /**
     * Decode the signature data. Verify that the object identifier matches
     * and return the message digest.
     */
    public static byte[] decodeSignature(ObjectIdentifier oid, byte[] sig)
            throws IOException {
        // Enforce strict DER checking for signatures
        DerInputStream in = new DerInputStream(sig, 0, sig.length, false);
        DerValue[] values = in.getSequence(2);
        if ((values.length != 2) || (in.available() != 0)) {
            throw new IOException("SEQUENCE length error");
        }
        AlgorithmId algId = AlgorithmId.parse(values[0]);
        if (algId.getOID().equals((Object)oid) == false) {
            throw new IOException("ObjectIdentifier mismatch: "
                + algId.getOID());
        }
        if (algId.getEncodedParams() != null) {
            throw new IOException("Unexpected AlgorithmId parameters");
        }
        byte[] digest = values[1].getOctetString();
        return digest;
    }

    // set parameter, not supported. See JCA doc
    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    // See JCA doc
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameters accepted");
        }
    }

    // get parameter, not supported. See JCA doc
    @Deprecated
    @Override
    protected Object engineGetParameter(String param)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    // See JCA doc
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    // Nested class for MD2withRSA signatures
    public static final class MD2withRSA extends SDFRSASignature {
        public MD2withRSA() {
            super("MD2", AlgorithmId.MD2_oid, 10);
        }
    }

    // Nested class for MD5withRSA signatures
    public static final class MD5withRSA extends SDFRSASignature {
        public MD5withRSA() {
            super("MD5", AlgorithmId.MD5_oid, 10);
        }
    }

    // Nested class for SHA1withRSA signatures
    public static final class SHA1withRSA extends SDFRSASignature {
        public SHA1withRSA() {
            super("SHA-1", AlgorithmId.SHA_oid, 7);
        }
    }

    // Nested class for SHA224withRSA signatures
    public static final class SHA224withRSA extends SDFRSASignature {
        public SHA224withRSA() {
            super("SHA-224", AlgorithmId.SHA224_oid, 11);
        }
    }

    // Nested class for SHA256withRSA signatures
    public static final class SHA256withRSA extends SDFRSASignature {
        public SHA256withRSA() {
            super("SHA-256", AlgorithmId.SHA256_oid, 11);
        }
    }

    // Nested class for SHA384withRSA signatures
    public static final class SHA384withRSA extends SDFRSASignature {
        public SHA384withRSA() {
            super("SHA-384", AlgorithmId.SHA384_oid, 11);
        }
    }

    // Nested class for SHA512withRSA signatures
    public static final class SHA512withRSA extends SDFRSASignature {
        public SHA512withRSA() {
            super("SHA-512", AlgorithmId.SHA512_oid, 11);
        }
    }

    // Nested class for SHA512/224withRSA signatures
    public static final class SHA512_224withRSA extends SDFRSASignature {
        public SHA512_224withRSA() {
            super("SHA-512/224", AlgorithmId.SHA512_224_oid, 11);
        }
    }

    // Nested class for SHA512/256withRSA signatures
    public static final class SHA512_256withRSA extends SDFRSASignature {
        public SHA512_256withRSA() {
            super("SHA-512/256", AlgorithmId.SHA512_256_oid, 11);
        }
    }
}
