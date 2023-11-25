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

import org.openeuler.sun.security.ec.BGECPrivateKey;
import org.openeuler.sun.security.ec.BGECPublicKey;
import org.openeuler.util.GMUtil;
import org.openeuler.util.Util;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ECUtil;

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import javax.crypto.Cipher;

public class SM2Cipher extends CipherSpi {
    public enum Mode {
        C1C2C3, C1C3C2;
    }

    private ByteArrayOutputStream byteBuf = new ByteArrayOutputStream();
    private MessageDigest digest = MessageDigest.getInstance("SM3");

    private SecureRandom random;
    private ECKey ecKey;

    private Mode outputMode = Mode.C1C3C2;
    private int cipherMode = -1;
    private int curveLength;

    public SM2Cipher() throws NoSuchAlgorithmException {
    }

    /**
     * Sets the mode of this cipher.
     *
     * @param mode the cipher mode
     * @throws NoSuchAlgorithmException if the requested cipher mode does
     *                                  not exist
     */
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        String modeName = mode.toUpperCase();

        if (!modeName.equals("NONE")) {
            throw new IllegalArgumentException("can't support mode " + mode);
        }
    }

    /**
     * Sets the padding mechanism of this cipher.
     *
     * @param padding the padding mechanism
     * @throws NoSuchPaddingException if the requested padding mechanism
     *                                does not exist
     */
    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        String paddingName = padding.toUpperCase();

        if (!paddingName.equals("NOPADDING")) {
            throw new NoSuchPaddingException("padding not available with SM2Cipher");
        }
    }

    /**
     * Returns the block size (in bytes).
     *
     * @return the block size (in bytes), or 0 if the underlying algorithm is
     * not a block cipher
     */
    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    /**
     * Returns the length in bytes that an output buffer would
     * need to be in order to hold the result of the next <code>update</code>
     * or <code>doFinal</code> operation, given the input length
     * <code>inputLen</code> (in bytes).
     *
     * <p>This call takes into account any unprocessed (buffered) data from a
     * previous <code>update</code> call, padding, and AEAD tagging.
     *
     * <p>The actual output length of the next <code>update</code> or
     * <code>doFinal</code> call may be smaller than the length returned by
     * this method.
     *
     * @param inputLen the input length (in bytes)
     * @return the required output buffer size (in bytes)
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        throw new UnsupportedOperationException("engineGetOutputSize");
    }

    /**
     * Returns the initialization vector (IV) in a new buffer.
     *
     * <p> This is useful in the context of password-based encryption or
     * decryption, where the IV is derived from a user-provided passphrase.
     *
     * @return the initialization vector in a new buffer, or null if the
     * underlying algorithm does not use an IV, or if the IV has not yet
     * been set.
     */
    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    /**
     * Returns the parameters used with this cipher.
     *
     * <p>The returned parameters may be the same that were used to initialize
     * this cipher, or may contain a combination of default and random
     * parameter values used by the underlying cipher implementation if this
     * cipher requires algorithm parameters but was not initialized with any.
     *
     * @return the parameters used with this cipher, or null if this cipher
     * does not use any parameters.
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected byte[] engineWrap(Key key)
            throws IllegalBlockSizeException, InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }
        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Cannot get an encoding of " +
                    "the key to be wrapped");
        }
        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (wrappedKey == null || wrappedKey.length == 0) {
            throw new InvalidKeyException("The wrappedKey cannot be null or empty");
        }
        byte[] unWrappedKey;
        try {
            unWrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Unwrapping failed", e);
        }
        return ConstructKeys.constructKey(unWrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    /**
     * Initializes this cipher with a key and a source
     * of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher requires any algorithm parameters that cannot be
     * derived from the given <code>key</code>, the underlying cipher
     * implementation is supposed to generate the required parameters itself
     * (using provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidKeyException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * {@link #engineGetParameters() engineGetParameters} or
     * {@link #engineGetIV() engineGetIV} (if the parameter is an IV).
     *
     * <p>If this cipher requires algorithm parameters that cannot be
     * derived from the input parameters, and there are no reasonable
     * provider-specific default values, initialization will
     * necessarily fail.
     *
     * <p>If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     *
     * <p>Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of
     *               the following:
     *               <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     *               <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key    the encryption key
     * @param random the source of randomness
     * @throws InvalidKeyException           if the given key is inappropriate for
     *                                       initializing this cipher, or requires
     *                                       algorithm parameters that cannot be
     *                                       determined from the given key.
     * @throws UnsupportedOperationException if {@code opmode} is
     *                                       {@code WRAP_MODE} or {@code UNWRAP_MODE} is not implemented
     *                                       by the cipher.
     */
    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("Parameters not supported: " + e.getMessage());
        }
    }

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher requires any algorithm parameters and
     * <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * {@link #engineGetParameters() engineGetParameters} or
     * {@link #engineGetIV() engineGetIV} (if the parameter is an IV).
     *
     * <p>If this cipher requires algorithm parameters that cannot be
     * derived from the input parameters, and there are no reasonable
     * provider-specific default values, initialization will
     * necessarily fail.
     *
     * <p>If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     *
     * <p>Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of
     *               the following:
     *               <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     *               <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key    the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     * @throws InvalidKeyException                if the given key is inappropriate for
     *                                            initializing this cipher
     * @throws InvalidAlgorithmParameterException if the given algorithm
     *                                            parameters are inappropriate for this cipher,
     *                                            or if this cipher requires
     *                                            algorithm parameters and <code>params</code> is null.
     * @throws UnsupportedOperationException      if {@code opmode} is
     *                                            {@code WRAP_MODE} or {@code UNWRAP_MODE} is not implemented
     *                                            by the cipher.
     */
    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            if (key instanceof BGECPublicKey) {
                this.ecKey = (BGECPublicKey) key;
            } else if (key instanceof ECPublicKey) {
                this.ecKey = (ECPublicKey) key;
            } else {
                throw new InvalidKeyException("must be passed public EC key for encryption");
            }
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            if (key instanceof BGECPrivateKey) {
                this.ecKey = (BGECPrivateKey) key;
            } else if (key instanceof ECPrivateKey) {
                this.ecKey = (ECPrivateKey) key;
            } else {
                throw new InvalidKeyException("must be passed private EC key for decryption");
            }
        } else {
            throw new InvalidParameterException("wrong cipher mode, must be ENCRYPT_MODE or WRAP_MODE or DECRYPT_MODE or UNWRAP_MODE");
        }

        this.random = random == null ? new SecureRandom() : random;
        this.curveLength = (this.ecKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        this.cipherMode = opmode;
        this.byteBuf.reset();
    }

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher requires any algorithm parameters and
     * <code>params</code> is null, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being
     * initialized for encryption or key wrapping, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
     * initialized for decryption or key unwrapping.
     * The generated parameters can be retrieved using
     * {@link #engineGetParameters() engineGetParameters} or
     * {@link #engineGetIV() engineGetIV} (if the parameter is an IV).
     *
     * <p>If this cipher requires algorithm parameters that cannot be
     * derived from the input parameters, and there are no reasonable
     * provider-specific default values, initialization will
     * necessarily fail.
     *
     * <p>If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     *
     * <p>Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing
     * it.
     *
     * @param opmode the operation mode of this cipher (this is one of
     *               the following:
     *               <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     *               <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key    the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     * @throws InvalidKeyException                if the given key is inappropriate for
     *                                            initializing this cipher
     * @throws InvalidAlgorithmParameterException if the given algorithm
     *                                            parameters are inappropriate for this cipher,
     *                                            or if this cipher requires
     *                                            algorithm parameters and <code>params</code> is null.
     * @throws UnsupportedOperationException      if {@code opmode} is
     *                                            {@code WRAP_MODE} or {@code UNWRAP_MODE} is not implemented
     *                                            by the cipher.
     */
    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("Parameters not supported: " + params.getClass());
        }
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in a new buffer.
     *
     * @param input       the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     *                    starts
     * @param inputLen    the input length
     * @return the new buffer with the result, or null if the underlying
     * cipher is a block cipher and the input data is too short to result in a
     * new block.
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byteBuf.write(input, inputOffset, inputLen);
        return null;
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, are processed,
     * and the result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code> inclusive.
     *
     * <p>If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown.
     *
     * @param input        the input buffer
     * @param inputOffset  the offset in <code>input</code> where the input
     *                     starts
     * @param inputLen     the input length
     * @param output       the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     *                     is stored
     * @return the number of bytes stored in <code>output</code>
     * @throws ShortBufferException if the given output buffer is too small
     *                              to hold the result
     */
    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     * The data is encrypted or decrypted, depending on how this cipher was
     * initialized.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous <code>update</code>
     * operation, are processed, with padding (if requested) being applied.
     * If an AEAD mode such as GCM/CCM is being used, the authentication
     * tag is appended in the case of encryption, or verified in the
     * case of decryption.
     * The result is stored in a new buffer.
     *
     * <p>Upon finishing, this method resets this cipher object to the state
     * it was in when previously initialized via a call to
     * <code>engineInit</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>engineInit</code>) more data.
     *
     * <p>Note: if any exception is thrown, this cipher object may need to
     * be reset before it can be used again.
     *
     * @param input       the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     *                    starts
     * @param inputLen    the input length
     * @return the new buffer with the result
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws AEADBadTagException       if this cipher is decrypting in an
     *                                   AEAD mode (such as GCM/CCM), and the received authentication tag
     *                                   does not match the calculated value
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if (inputLen != 0) {
            byteBuf.write(input, inputOffset, inputLen);
        }

        try {
            if (cipherMode == Cipher.ENCRYPT_MODE || cipherMode == Cipher.WRAP_MODE) {
                try {
                    return encrypt(byteBuf.toByteArray(), 0, byteBuf.size());
                } catch (Exception e) {
                    throw new RuntimeException("decryption failed: " + e.getMessage());
                }
            } else if (cipherMode == Cipher.DECRYPT_MODE || cipherMode == Cipher.UNWRAP_MODE) {
                try {
                    return decrypt(byteBuf.toByteArray(), 0, byteBuf.size());
                } catch (Exception e) {
                    throw new RuntimeException("decryption failed: " + e.getMessage());
                }
            } else {
                throw new IllegalStateException("cipher not initialised");
            }
        } finally {
            byteBuf.reset();
        }
    }

    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     * The data is encrypted or decrypted, depending on how this cipher was
     * initialized.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code> inclusive, and any input
     * bytes that may have been buffered during a previous <code>update</code>
     * operation, are processed, with padding (if requested) being applied.
     * If an AEAD mode such as GCM/CCM is being used, the authentication
     * tag is appended in the case of encryption, or verified in the
     * case of decryption.
     * The result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code> inclusive.
     *
     * <p>If the <code>output</code> buffer is too small to hold the result,
     * a <code>ShortBufferException</code> is thrown.
     *
     * <p>Upon finishing, this method resets this cipher object to the state
     * it was in when previously initialized via a call to
     * <code>engineInit</code>.
     * That is, the object is reset and available to encrypt or decrypt
     * (depending on the operation mode that was specified in the call to
     * <code>engineInit</code>) more data.
     *
     * <p>Note: if any exception is thrown, this cipher object may need to
     * be reset before it can be used again.
     *
     * @param input        the input buffer
     * @param inputOffset  the offset in <code>input</code> where the input
     *                     starts
     * @param inputLen     the input length
     * @param output       the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     *                     is stored
     * @return the number of bytes stored in <code>output</code>
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size; or if this encryption algorithm is unable to
     *                                   process the input data provided.
     * @throws ShortBufferException      if the given output buffer is too small
     *                                   to hold the result
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     * @throws AEADBadTagException       if this cipher is decrypting in an
     *                                   AEAD mode (such as GCM/CCM), and the received authentication tag
     *                                   does not match the calculated value
     */
    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] buffer = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(buffer, 0, output, outputOffset, buffer.length);
        return buffer.length;
    }

    /**
     * Encrypt message using sm2 algorithm
     *
     * @param input       the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     *                    starts
     * @param inputLen    the input length
     * @return the new buffer with the result
     * @throws IOException
     * @throws InvalidKeyException
     */
    private byte[] encrypt(byte[] input, int inputOffset, int inputLen) throws IOException, InvalidKeyException {
        ECParameterSpec ecParameterSpec = this.ecKey.getParams();
        EllipticCurve curve = ecParameterSpec.getCurve();
        ECPoint Pb = ((ECPublicKey) this.ecKey).getW();

        ECPoint s = GMUtil.multiply(Pb, ecParameterSpec.getCofactor(), curve);
        if (s.equals(ECPoint.POINT_INFINITY)) {
            throw new InvalidKeyException("[h]Pb at infinity");
        }

        byte[] c1, t, x2, y2;
        ECPoint kPb, c1Point;
        do {
            BigInteger k;
            BigInteger n = ecParameterSpec.getOrder();
            do {
                int nBitLen = n.bitLength();
                k = Util.createRandomBigInteger(nBitLen, random);
            }
            while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(n) >= 0);

            c1Point = GMUtil.multiply(ecParameterSpec.getGenerator(), k, curve);
            c1 = ECUtil.encodePoint(c1Point, curve);

            kPb = GMUtil.multiply(Pb, k, curve);

            x2 = Util.asUnsignedByteArray(curveLength, kPb.getAffineX());
            y2 = Util.asUnsignedByteArray(curveLength, kPb.getAffineY());
            byte[] z = Util.concatenate(x2, y2);

            t = KDF(z, inputLen);
        }
        while (isAllZero(t));

        byte[] c2 = new byte[inputLen];
        for (int i = 0; i < inputLen; i++) {
            c2[i] = (byte) (input[inputOffset + i] ^ t[i]);
        }

        digest.update(x2);
        digest.update(input, inputOffset, inputLen);
        digest.update(y2);

        byte[] c3 = digest.digest();

        DerOutputStream out = new DerOutputStream();
        out.putInteger(c1Point.getAffineX());
        out.putInteger(c1Point.getAffineY());
        if (outputMode == Mode.C1C3C2) {
            out.putOctetString(c3);
            out.putOctetString(c2);
        } else if (outputMode == Mode.C1C2C3) {
            out.putOctetString(c2);
            out.putOctetString(c3);
        }
        DerValue result = new DerValue(DerValue.tag_Sequence, out.toByteArray());
        try {
            return result.toByteArray();
        } catch (IOException e) {
            throw new IOException("DERSequence getEncoded failed", e);
        }
    }

    /**
     * Decrypt message using sm2 algorithm
     *
     * @param input       the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     *                    starts
     * @param inputLen    the input length
     * @return the new buffer with the result
     * @throws IOException
     * @throws InvalidKeyException
     */
    private byte[] decrypt(byte[] input, int inputOffset, int inputLen) throws IOException, InvalidKeyException {
        byte[] bytes = new byte[inputLen];
        System.arraycopy(input, inputOffset, bytes, 0, inputLen);

        DerInputStream inDer = new DerInputStream(bytes, inputOffset, inputLen, false);
        DerValue[] values = inDer.getSequence(2);

        // check number of components in the read sequence
        // and trailing data
        if ((values.length != 4) || (inDer.available() != 0)) {
            throw new IOException("Invalid encoding for signature");
        }

        BigInteger x = values[0].getPositiveBigInteger();
        BigInteger y = values[1].getPositiveBigInteger();
        ECPoint c1Point = new SM2Point(x, y);

        ECParameterSpec ecParameterSpec = ((ECPrivateKey) this.ecKey).getParams();
        EllipticCurve curve = ecParameterSpec.getCurve();

        byte[] c1 = ECUtil.encodePoint(c1Point, curve);
        byte[] c2, c3;
        if (outputMode == Mode.C1C3C2) {
            c3 = values[2].getOctetString();
            c2 = values[3].getOctetString();
        } else {
            c2 = values[2].getOctetString();
            c3 = values[3].getOctetString();
        }

        if (!GMUtil.checkECPoint(c1Point, curve)) {
            throw new InvalidKeyException("C1 does not satisfy the curve equation");
        }

        ECPoint s = GMUtil.multiply(c1Point, ecParameterSpec.getCofactor(), curve);
        if (s.equals(ECPoint.POINT_INFINITY)) {
            throw new InvalidKeyException("[h]C1 at infinity");
        }

        // temp = (x2, y2) = [dB]C1
        ECPoint temp = GMUtil.multiply(c1Point, ((ECPrivateKey) this.ecKey).getS(), curve);

        byte[] x2 = Util.asUnsignedByteArray(curveLength, temp.getAffineX());
        byte[] y2 = Util.asUnsignedByteArray(curveLength, temp.getAffineY());
        byte[] z = Util.concatenate(x2, y2);

        byte[] t = KDF(z, c2.length);
        if (isAllZero(t)) {
            throw new InvalidKeyException("invalid cipher text");
        }

        // m_ just is m'
        byte[] m_ = new byte[c2.length];
        for (int i = 0; i < c2.length; i++) {
            m_[i] = (byte) (c2[i] ^ t[i]);
        }

        digest.update(x2);
        digest.update(m_);
        digest.update(y2);
        byte[] u = digest.digest();

        if (java.util.Arrays.equals(u, c3)) {
            return m_;
        } else {
            throw new InvalidKeyException("invalid cipher text");
        }
    }

    private byte[] KDF(byte[] z, int klen) {
        int digestSize = digest.getDigestLength();
        byte[] k = new byte[klen];
        byte[] ctBuf = new byte[4];
        int off = 0;
        int ct = 1;

        while (off < klen) {
            Util.intToBigEndian(ct++, ctBuf, 0);

            digest.update(z);
            digest.update(ctBuf);

            byte[] hash = digest.digest();
            if (klen - off >= digestSize) {
                System.arraycopy(hash, 0, k, off, digestSize);
                off += digestSize;
            } else {
                System.arraycopy(hash, 0, k, off, klen - off);
                off = klen;
            }
        }
        return k;
    }

    private boolean isAllZero(byte[] t) {
        for (byte b : t) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
