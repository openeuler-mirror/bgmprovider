/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd. All rights reserved.
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

package org.openeuler.sdf.jca.asymmetric;

import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.jca.commons.SDFKeyUtil;
import org.openeuler.sdf.jca.commons.SDFSM2CipherMode;
import org.openeuler.sdf.jca.commons.SDFUtil;
import org.openeuler.sdf.wrapper.SDFSM2CipherNative;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * SDF SM2 Cipher
 */
public class SDFSM2Cipher extends CipherSpi {

    // mode constant for public key encryption
    private final static int MODE_ENCRYPT = 1;
    // mode constant for private key decryption
    private final static int MODE_DECRYPT = 2;

    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private ECKey ecKey;
    private SDFSM2CipherMode outputMode = SDFSM2CipherMode.C1C3C2;
    private int mode;
    private int curveLength;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("NONE")) {
            throw new IllegalArgumentException("can't support mode " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NOPADDING")) {
            throw new NoSuchPaddingException("padding not available with SDFSM2Cipher");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        throw new UnsupportedOperationException("engineGetOutputSize");
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        init(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(opmode, key);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        update(input, inputOffset, inputLen);
        return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        update(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return doFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] buf = doFinal(input, inputOffset, inputLen);
        System.arraycopy(buf, 0, output, outputOffset, buf.length);
        return buf.length;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }
        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Cannot get an encoding of " +
                    "the key to be wrapped");
        }
        return doFinal(encoded, 0, encoded.length);
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        if (wrappedKey == null || wrappedKey.length == 0) {
            throw new InvalidKeyException("The wrappedKey cannot be null or empty");
        }
        byte[] unWrappedKey = doFinal(wrappedKey, 0, wrappedKey.length);
        return SDFKeyUtil.constructKey(wrappedKeyType, unWrappedKey, wrappedKeyAlgorithm);
    }

    void init(int opmode, Key key) throws InvalidKeyException {
        switch (opmode) {
            case Cipher.ENCRYPT_MODE:
            case Cipher.WRAP_MODE:
                this.mode = MODE_ENCRYPT;
                if (!(key instanceof ECPublicKey)) {
                    throw new InvalidKeyException("should be EC public key for encryption");
                }
                this.ecKey = (ECPublicKey) key;
                break;
            case Cipher.DECRYPT_MODE:
            case Cipher.UNWRAP_MODE:
                this.mode = MODE_DECRYPT;
                if (!(key instanceof ECPrivateKey)) {
                    throw new InvalidKeyException("should be EC private key for decryption");
                }
                this.ecKey = (ECPrivateKey) key;
                break;
            default:
                throw new InvalidKeyException("Unknown mode: " + opmode);
        }
        this.curveLength = this.ecKey.getParams().getCurve().getField().getFieldSize();
        this.buffer.reset();
    }

    void update(byte[] input, int inputOffset, int inputLen) {
        if (inputLen > 0) {
            buffer.write(input, inputOffset, inputLen);
        }
    }

    byte[] doFinal(byte[] input, int inputOffset, int inputLen) {
        update(input, inputOffset, inputLen);

        byte[] result;
        try {
            switch (mode) {
                case MODE_ENCRYPT:
                    result = encrypt(buffer.toByteArray());
                    break;
                case MODE_DECRYPT:
                    result = decrypt(buffer.toByteArray());
                    break;
                default:
                    throw new AssertionError("Internal error");
            }
        } finally {
            buffer.reset();
        }
        return result;
    }

    private byte[] encrypt(byte[] in) {
        if (in == null || in.length == 0) {
            throw new IllegalArgumentException("data should not be empty");
        }
        byte[][] cipherParams;
        ECPublicKey publicKey = (ECPublicKey) ecKey;
        try {
            int size = (curveLength + 7) / 8;
            Object[] pubKeyArr = {
                    SDFUtil.asUnsignedByteArray(size, publicKey.getW().getAffineX()),
                    SDFUtil.asUnsignedByteArray(size, publicKey.getW().getAffineY())
            };
            cipherParams = SDFSM2CipherNative.nativeSM2Encrypt(pubKeyArr, in);
            System.out.println(Arrays.toString(cipherParams[0]));
            System.out.println(Arrays.toString(cipherParams[1]));
            System.out.println(Arrays.toString(cipherParams[2]));
            System.out.println(Arrays.toString(cipherParams[3]));
            return SDFUtil.encodeECCCipher(outputMode, cipherParams);
        } catch (Exception e) {
            throw new SDFRuntimeException(e);
        }
    }

    private byte[] decrypt(byte[] in) {
        if (in == null || in.length == 0) {
            throw new IllegalArgumentException("encData should not be empty");
        }
        byte[] result;
        ECPrivateKey privateKey = (ECPrivateKey) ecKey;
        try {
            byte[] priKeyArr = SDFUtil.getPrivateKeyBytes(privateKey);
            byte[] pinArr = SDFUtil.getPinOfPrivateKey(privateKey);
            byte[][] sm2CipherParams = SDFUtil.decodeECCCipher(outputMode, in, curveLength);
            result = SDFSM2CipherNative.nativeSM2Decrypt(
                    priKeyArr, pinArr, sm2CipherParams
            );
        } catch (Exception e) {
            throw new SDFRuntimeException("decrypt failed.", e);
        }
        return result;
    }
}