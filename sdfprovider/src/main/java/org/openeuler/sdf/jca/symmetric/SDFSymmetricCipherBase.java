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

package org.openeuler.sdf.jca.symmetric;

import org.openeuler.sdf.commons.constant.SDFConstant;
import org.openeuler.sdf.commons.constant.SDFDataKeyType;
import org.openeuler.sdf.commons.exception.SDFException;
import org.openeuler.sdf.commons.exception.SDFRuntimeException;
import org.openeuler.sdf.commons.key.SDFEncryptKey;
import org.openeuler.sdf.jca.commons.SDFKeyUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Locale;

import static org.openeuler.sdf.wrapper.SDFSymmetricCipherNative.nativeCipherFinal;
import static org.openeuler.sdf.wrapper.SDFSymmetricCipherNative.nativeCipherInit;
import static org.openeuler.sdf.wrapper.SDFSymmetricCipherNative.nativeCipherUpdate;

public abstract class SDFSymmetricCipherBase extends CipherSpi {
    private final SDFDataKeyType dataKeyType;
    private SDFPadding padding;
    private SDFMode mode;
    private final int blockSize;
    protected final int supportedKeySize;
    private String cipherAlgo;
    private SecretKey secretKey;
    private byte[] iv;
    // Use encrypted secret Key
    private boolean isEncKey = false;
    // SDF Symmetric Context
    private SDFSymmetricContext context = null;
    private boolean initialized = false;
    // Do encrypt or decrypt
    private boolean encrypt = false;
    // Cache length need to doFinal
    private int bytesBuffered = 0;

    SDFSymmetricCipherBase(SDFDataKeyType dataKeyType, SDFMode mode, SDFPadding padding, int blockSize, int supportedKeySize) {
        this.dataKeyType = dataKeyType;
        this.mode = mode;
        this.padding = padding;
        this.blockSize = blockSize;
        this.supportedKeySize = supportedKeySize;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode == null) {
            throw new NoSuchAlgorithmException("null mode");
        }
        String modeUpperCase = mode.toUpperCase(Locale.ENGLISH);
        if (modeUpperCase.equalsIgnoreCase("ECB")) {
            this.mode = SDFMode.ECB;
        } else if (modeUpperCase.equalsIgnoreCase("CBC")) {
            this.mode = SDFMode.CBC;
        } else {
            throw new NoSuchAlgorithmException("Unsupported mode " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (padding == null) {
            throw new NoSuchPaddingException("null padding");
        }
        if (SDFPadding.NOPADDING.getPadding().equals(padding)) {
            this.padding = SDFPadding.NOPADDING;
        } else if (SDFPadding.PKCS5PADDING.getPadding().equals(padding)) {
            this.padding = SDFPadding.PKCS5PADDING;
        } else {
            throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return blockSize;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return getOutputSizeByOperation(inputLen, true);
    }

    @Override
    protected byte[] engineGetIV() {
        return iv == null ? null : iv.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (iv == null) {
            return null;
        }
        AlgorithmParameterSpec spec;
        AlgorithmParameters params;
        spec = new IvParameterSpec(iv.clone());
        try {
            params = AlgorithmParameters.getInstance(this.dataKeyType.getAlgorithm());
            params.init(spec);
            return params;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not encode parameters", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            implInit(opmode, key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("SDFSymmetricCipher init failed", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        implInit(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        String paramType = null;
        if (params != null) {
            try {
                if (mode == SDFMode.GCM) {
                    paramType = "GCM";
                    spec = params.getParameterSpec(GCMParameterSpec.class);
                } else {
                    paramType = "IV";
                    spec = params.getParameterSpec(IvParameterSpec.class);
                }
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException
                        ("Wrong parameter type: " + paramType + " expected");
            }
        }
        implInit(opmode, key, spec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] out = new byte[getOutputSizeByOperation(inputLen, false)];
        int outLen = implUpdate(input, inputOffset, inputLen, out, 0);
        if (outLen == 0) {
            return new byte[0];
        } else if (out.length != outLen) {
            out = Arrays.copyOf(out, outLen);
        }
        return out;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        int min = getOutputSizeByOperation(inputLen, false);
        if (output == null || output.length - outputOffset < min) {
            throw new ShortBufferException("min " + min + "-byte buffer needed");
        }
        return implUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException,
            BadPaddingException {
        byte[] out = new byte[getOutputSizeByOperation(inputLen, true)];
        try {
            int outLen = implDoFinal(input, inputOffset, inputLen, out, 0);
            if (out.length != outLen) {
                out = Arrays.copyOf(out, outLen);
            }
            return out;
        } catch (ShortBufferException e) {
            throw new ProviderException(e);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        return implDoFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] res;
        try {
            byte[] encodedKey = key.getEncoded();
            if (encodedKey == null || encodedKey.length == 0) {
                throw new InvalidKeyException("Cannot get an encoding of the key to be wrapped");
            }
            res = engineDoFinal(encodedKey, 0, encodedKey.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrapping failed", e);
        }
        return res;
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] encodedKey;
        try {
            encodedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Unwrapping failed", e);
        }
        return SDFKeyUtil.constructKey(wrappedKeyType, encodedKey, wrappedKeyAlgorithm);
    }

    @Override
    protected int engineUpdate(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        try {
            return bufferCrypt(input, output, true);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // never thrown for engineUpdate()
            throw new ProviderException("Internal error in update()");
        }
    }

    @Override
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return bufferCrypt(input, output, false);
    }

    /**
     * Implementation for encryption using ByteBuffers. Used for both
     * engineUpdate() and engineDoFinal().
     */
    private int bufferCrypt(ByteBuffer input, ByteBuffer output,
                            boolean isUpdate) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        if ((input == null) || (output == null)) {
            throw new NullPointerException
                    ("Input and output buffers must not be null");
        }
        int inPos = input.position();
        int inLimit = input.limit();
        int inLen = inLimit - inPos;
        if (isUpdate && (inLen == 0)) {
            return 0;
        }
        int outLenNeeded = engineGetOutputSize(inLen);

        if (output.remaining() < outLenNeeded) {
            throw new ShortBufferException("Need at least " + outLenNeeded
                    + " bytes of space in output buffer");
        }

        // detecting input and output buffer overlap may be tricky
        // we can only write directly into output buffer when we
        // are 100% sure it's safe to do so

        boolean a1 = input.hasArray();
        boolean a2 = output.hasArray();
        int total = 0;

        if (a1) { // input has an accessible byte[]
            byte[] inArray = input.array();
            int inOfs = input.arrayOffset() + inPos;

            byte[] outArray;
            if (a2) { // output has an accessible byte[]
                outArray = output.array();
                int outPos = output.position();
                int outOfs = output.arrayOffset() + outPos;

                // check array address and offsets and use temp output buffer
                // if output offset is larger than input offset and
                // falls within the range of input data
                boolean useTempOut = false;
                if (inArray == outArray &&
                        ((inOfs < outOfs) && (outOfs < inOfs + inLen))) {
                    useTempOut = true;
                    outArray = new byte[outLenNeeded];
                    outOfs = 0;
                }
                if (isUpdate) {
                    total = engineUpdate(inArray, inOfs, inLen, outArray, outOfs);
                } else {
                    total = engineDoFinal(inArray, inOfs, inLen, outArray, outOfs);
                }
                if (useTempOut) {
                    output.put(outArray, outOfs, total);
                } else {
                    // adjust output position manually
                    output.position(outPos + total);
                }
            } else { // output does not have an accessible byte[]
                if (isUpdate) {
                    outArray = engineUpdate(inArray, inOfs, inLen);
                } else {
                    outArray = engineDoFinal(inArray, inOfs, inLen);
                }
                if (outArray != null && outArray.length != 0) {
                    output.put(outArray);
                    total = outArray.length;
                }
            }
            // adjust input position manually
            input.position(inLimit);
        } else { // input does not have an accessible byte[]
            // have to assume the worst, since we have no way of determine
            // if input and output overlaps or not
            byte[] tempOut = new byte[outLenNeeded];
            int outOfs = 0;

            byte[] tempIn = new byte[getTempArraySize(inLen)];
            do {
                int chunk = Math.min(inLen, tempIn.length);
                if (chunk > 0) {
                    input.get(tempIn, 0, chunk);
                }
                int n;
                if (isUpdate || (inLen > chunk)) {
                    n = engineUpdate(tempIn, 0, chunk, tempOut, outOfs);
                } else {
                    n = engineDoFinal(tempIn, 0, chunk, tempOut, outOfs);
                }
                outOfs += n;
                total += n;
                inLen -= chunk;
            } while (inLen > 0);
            if (total > 0) {
                output.put(tempOut, 0, total);
            }
        }
        return total;
    }


    // copied from sun.security.jca.JCAUtil
    // will be changed to reference that method once that code has been
    // integrated and promoted
    private int getTempArraySize(int totalSize) {
        return Math.min(4096, totalSize);
    }

    protected int getOutputSizeByOperation(int inLen, boolean isDoFinal) {
        int ret;
        if (inLen <= 0) {
            inLen = 0;
        }
        if (padding == SDFPadding.NOPADDING) {
            ret = inLen + bytesBuffered;
        } else {
            int len = inLen + bytesBuffered;

            len += (len % blockSize != 0 || encrypt) ? blockSize : 0;
            ret = len - (len % blockSize);
        }
        return ret;
    }

    protected void ensureInitialized() {
        if (!initialized) {
            // init cipher context
            long ctxHandleAddress = getContextHandleAddress(mode.getMode(), padding, secretKey.getEncoded(),
                    iv, encrypt);
            context = new SDFSymmetricContext(ctxHandleAddress);
            initialized = true;
        }
    }

    private void implInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        checkKey(key);
        this.encrypt = (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE);

        byte[] ivBytes = null;
        if (params != null) {
            if (mode == SDFMode.GCM) {
                if (params instanceof GCMParameterSpec) {
                    int tagLen = ((GCMParameterSpec)params).getTLen();
                    if (tagLen < 96 || tagLen > 128 || ((tagLen & 0x07) != 0)) {
                        throw new InvalidAlgorithmParameterException
                                ("Unsupported TLen value; must be one of " +
                                        "{128, 120, 112, 104, 96}");
                    }
                    tagLen = tagLen >> 3;
                    ivBytes = ((GCMParameterSpec)params).getIV();
                } else {
                    throw new InvalidAlgorithmParameterException
                            ("Unsupported parameter: " + params);
                }
            } else {
                if (params instanceof IvParameterSpec) {
                    ivBytes = ((IvParameterSpec)params).getIV();
                    if ((ivBytes == null) || (ivBytes.length != blockSize)) {
                        throw new InvalidAlgorithmParameterException
                                ("Wrong IV length: must be " + blockSize +
                                        " bytes long");
                    }
                } else {
                    throw new InvalidAlgorithmParameterException
                            ("Unsupported parameter: " + params);
                }
            }
        }
        if (mode == SDFMode.ECB) {
            if (ivBytes != null) {
                throw new InvalidAlgorithmParameterException
                        ("ECB mode cannot use IV");
            }
        } else if (ivBytes == null) {
            if (!encrypt) {
                throw new InvalidAlgorithmParameterException("Parameters missing");
            }
            if (random == null) {
                random = new SecureRandom();
            }
            if (mode == SDFMode.GCM) {
                ivBytes = new byte[12];
            } else {
                ivBytes = new byte[blockSize];
            }
            random.nextBytes(ivBytes);
        }
        this.secretKey = (SecretKey) key;
        this.iv = ivBytes;
        this.cipherAlgo = createCipherName(this.dataKeyType.getAlgorithm(), mode.getMode());
    }

    private static String createCipherName(String algorithm, String mode) {
        return (algorithm + "-" + mode).toUpperCase();
    }

    private int implUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (inputLen <= 0) {
            return 0;
        }
        int outLen;
        try {
            ensureInitialized();
            outLen = nativeCipherUpdate(context.getAddress(), input, inputOffset, inputLen,
                    output, outputOffset, encrypt);
        } catch (SDFException e) {
            reset();
            throw new SDFRuntimeException("SDFSymmetricCipher nativeUpdate failed for " + dataKeyType.getAlgorithm(), e);
        }
        bytesBuffered += (inputLen - outLen);

        return outLen;
    }


    private int implDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        int outLen = 0;
        int min = getOutputSizeByOperation(inputLen, true);
        try {
            if (output == null || output.length - outputOffset < min) {
                throw new ShortBufferException("min " + min + "-byte buffer needed");
            }

            // decrypt mode and inputLen is 0, return 0
            /*if ((!encrypt) && (inputLen == 0)) {
                return outLen;
            }*/

            if (input == null) {
                input = new byte[0];
            }
            ensureInitialized();
            outLen = nativeCipherFinal(context.getAddress(), input, inputOffset, inputLen,
                    output, outputOffset, encrypt);
        } catch (SDFException e) {
            throw new SDFRuntimeException("SDFSymmetricCipher nativeCipherFinal failed for " + dataKeyType.getAlgorithm(), e);
        } finally {
            reset();
        }
        return outLen;
    }

    protected void reset() {
        initialized = false;
        bytesBuffered = 0;

        // free cipher context
        if (context != null) {
            context.getReference().dispose();
            context = null;
        }
    }

    // get new cipher context
    protected long getContextHandleAddress(String mode, SDFPadding padding, byte[] keyValue, byte[] iv,
                                           boolean encrypt) {
        long ctxHandleAddress;
        try {
            ctxHandleAddress = nativeCipherInit(dataKeyType.getType(), mode, SDFPadding.PKCS5PADDING.equals(padding), keyValue, iv, encrypt);
        } catch (SDFException e) {
            throw new SDFRuntimeException("SDFSymmetricCipher nativeCipherInit failed for " + this.dataKeyType.getAlgorithm(), e);
        }
        return ctxHandleAddress;
    }

    private void checkKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("No key given");
        }
        if (!dataKeyType.getAlgorithm().equalsIgnoreCase(key.getAlgorithm())) {
            throw new InvalidKeyException("Key algorithm must be " + dataKeyType.getAlgorithm());
        }
        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("RAW key bytes missing");
        }
        if (key instanceof SDFEncryptKey) {
            this.isEncKey = ((SDFEncryptKey) key).isEncKey();
        }
        // Check encrypted SecretKey
        if (isEncKey) {
            checkEncKeySize(keyBytes.length);
        } else {
            checkPlainKeySize(keyBytes.length);
        }
    }

    private void checkEncKeySize(int keySize) throws InvalidKeyException {
        if (keySize != SDFConstant.ENC_SYS_PRIVATE_KEY_SIZE) {
            throw new InvalidKeyException("Invalid " + dataKeyType.getAlgorithm() + " encrypted key length :" + keySize + " bytes, " +
                    "only support " + SDFConstant.ENC_SYS_PRIVATE_KEY_SIZE + " bytes");
        }
    }

    protected void checkPlainKeySize(int keySize) throws InvalidKeyException {
        if (keySize != supportedKeySize) {
            throw new InvalidKeyException("Invalid " + dataKeyType.getAlgorithm() + " plain key length :" + keySize + "bytes, " +
                    "only support " + supportedKeySize + " bytes");
        }
    }
}