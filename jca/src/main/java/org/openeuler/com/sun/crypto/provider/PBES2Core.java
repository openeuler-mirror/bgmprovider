/*
 * Copyright (c) 2012, 2015, Oracle and/or its affiliates. All rights reserved.
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

package org.openeuler.com.sun.crypto.provider;

import org.openeuler.BGMJCEProvider;

import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This class represents password-based encryption as defined by the PKCS #5
 * standard.
 * These algorithms implement PBE with HmacSHA1/HmacSHA2-family and AES-CBC.
 * Padding is done as described in PKCS #5.
 */
abstract class PBES2Core extends CipherSpi {
    // constant for an empty byte array
    private final static byte[] B0 = new byte[0];
    private static final int DEFAULT_SALT_LENGTH = 20;
    private static final int DEFAULT_COUNT = 4096;
    private static final String ECB_MODE = "ECB";
    private static final String CBC_MODE = "CBC";
    private static final Set<String> SUPPORTED_MODES = new HashSet<>(
            Arrays.asList(ECB_MODE, CBC_MODE));
    // the encapsulated cipher
    private final Cipher cipher;
    private final int keyLength; // in bits
    private final int blkSize; // in bits
    private final SecretKeyFactory kdf;
    private final String pbeAlgo;
    private final String cipherAlgo;
    private int iCount = DEFAULT_COUNT;
    private byte[] salt = null;
    private IvParameterSpec ivSpec = null;
    private String mode;
    private String padding;

    /**
     * Creates an instance of PBE Scheme 2 according to the selected
     * password-based key derivation function and encryption scheme.
     */
    PBES2Core(String kdfAlgo, String cipherAlgo, int keySize, String mode, String padding)
            throws NoSuchAlgorithmException, NoSuchPaddingException {

        this.cipherAlgo = cipherAlgo;
        this.mode = mode;
        this.padding = padding;
        keyLength = keySize * 8;
        pbeAlgo = "PBEWith" + kdfAlgo + "And" + cipherAlgo + "_" + keyLength + "/" + mode + "/" + padding;
        if (cipherAlgo.equals("SM4")) {
            blkSize = keySize;
            cipher = Cipher.getInstance(cipherAlgo + "/" + mode + "/" + padding);
            kdf = SecretKeyFactory.getInstance("PBKDF2With" + kdfAlgo);
        } else {
            throw new NoSuchAlgorithmException("No Cipher implementation for " +
                    pbeAlgo);
        }
    }

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if ((mode != null) && (!SUPPORTED_MODES.contains(mode.toUpperCase(Locale.ENGLISH)))) {
            throw new NoSuchAlgorithmException("Invalid cipher mode: " + mode);
        }
    }

    protected void engineSetPadding(String paddingScheme)
        throws NoSuchPaddingException {
        if ((paddingScheme != null) &&
            (!paddingScheme.equalsIgnoreCase("PKCS5Padding"))) {
            throw new NoSuchPaddingException("Invalid padding scheme: " +
                                             paddingScheme);
        }
    }

    protected int engineGetBlockSize() {
        return blkSize;
    }

    protected int engineGetOutputSize(int inputLen) {
        return cipher.getOutputSize(inputLen);
    }

    protected byte[] engineGetIV() {
        return cipher.getIV();
    }

    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;
        if (salt == null) {
            // generate random salt and use default iteration count
            salt = new byte[DEFAULT_SALT_LENGTH];
            BGMJCEProvider.getRandom().nextBytes(salt);
            iCount = DEFAULT_COUNT;
        }
        if (!ECB_MODE.equals(this.mode) && ivSpec == null) {
            // generate random IV
            byte[] ivBytes = new byte[blkSize];
            BGMJCEProvider.getRandom().nextBytes(ivBytes);
            ivSpec = new IvParameterSpec(ivBytes);
        }
        PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, iCount, ivSpec);
        try {
            params = AlgorithmParameters.getInstance(pbeAlgo);
            params.init(pbeSpec);
        } catch (NoSuchAlgorithmException nsae) {
            // should never happen
            throw new RuntimeException("BGMJCEProvider called, but not configured");
        } catch (InvalidParameterSpecException ipse) {
            // should never happen
            throw new RuntimeException("PBEParameterSpec not supported");
        }
        return params;
    }

    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException ie) {
            InvalidKeyException ike =
                new InvalidKeyException("requires PBE parameters");
            ike.initCause(ie);
            throw ike;
        }
    }

    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        if (key == null) {
            throw new InvalidKeyException("Null key");
        }

        byte[] passwdBytes = key.getEncoded();
        char[] passwdChars = null;
        PBEKeySpec pbeSpec;
        try {
            if ((passwdBytes == null) ||
                    !(key.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3))) {
                throw new InvalidKeyException("Missing password");
            }

            // TBD: consolidate the salt, ic and IV parameter checks below

            // Extract salt and iteration count from the key, if present
            if (key instanceof javax.crypto.interfaces.PBEKey) {
                salt = ((javax.crypto.interfaces.PBEKey)key).getSalt();
                if (salt != null && salt.length < 8) {
                    throw new InvalidAlgorithmParameterException(
                            "Salt must be at least 8 bytes long");
                }
                iCount = ((javax.crypto.interfaces.PBEKey)key).getIterationCount();
                if (iCount == 0) {
                    iCount = DEFAULT_COUNT;
                } else if (iCount < 0) {
                    throw new InvalidAlgorithmParameterException(
                            "Iteration count must be a positive number");
                }
            }

            // Extract salt, iteration count and IV from the params, if present
            if (params == null) {
                if (salt == null) {
                    // generate random salt and use default iteration count
                    salt = new byte[DEFAULT_SALT_LENGTH];
                    random.nextBytes(salt);
                    iCount = DEFAULT_COUNT;
                }
                if (!ECB_MODE.equals(this.mode) && ((opmode == Cipher.ENCRYPT_MODE) ||
                        (opmode == Cipher.WRAP_MODE))) {
                    // generate random IV
                    byte[] ivBytes = new byte[blkSize];
                    random.nextBytes(ivBytes);
                    ivSpec = new IvParameterSpec(ivBytes);
                }
            } else {
                if (!(params instanceof PBEParameterSpec)) {
                    throw new InvalidAlgorithmParameterException
                            ("Wrong parameter type: PBE expected");
                }
                // salt and iteration count from the params take precedence
                byte[] specSalt = ((PBEParameterSpec) params).getSalt();
                if (specSalt != null && specSalt.length < 8) {
                    throw new InvalidAlgorithmParameterException(
                            "Salt must be at least 8 bytes long");
                }
                salt = specSalt;
                int specICount = ((PBEParameterSpec) params).getIterationCount();
                if (specICount == 0) {
                    specICount = DEFAULT_COUNT;
                } else if (specICount < 0) {
                    throw new InvalidAlgorithmParameterException(
                            "Iteration count must be a positive number");
                }
                iCount = specICount;

                AlgorithmParameterSpec specParams =
                        ((PBEParameterSpec) params).getParameterSpec();
                if (specParams != null) {
                    if (specParams instanceof IvParameterSpec) {
                        ivSpec = (IvParameterSpec)specParams;
                    } else {
                        throw new InvalidAlgorithmParameterException(
                                "Wrong parameter type: IV expected");
                    }
                }

                if (ECB_MODE.equals(this.mode)) {
                    if (ivSpec != null) {
                        throw new InvalidAlgorithmParameterException("ECB mode cannot use IV");
                    }
                } else if (ivSpec == null) {
                    if ((opmode == Cipher.ENCRYPT_MODE) ||
                            (opmode == Cipher.WRAP_MODE)) {
                        // generate random IV
                        byte[] ivBytes = new byte[blkSize];
                        random.nextBytes(ivBytes);
                        ivSpec = new IvParameterSpec(ivBytes);
                    } else {
                        throw new InvalidAlgorithmParameterException(
                                "Missing parameter type: IV expected");
                    }
                }
            }

            passwdChars = new char[passwdBytes.length];
            for (int i = 0; i < passwdChars.length; i++)
                passwdChars[i] = (char) (passwdBytes[i] & 0x7f);

            pbeSpec = new PBEKeySpec(passwdChars, salt, iCount, keyLength);
            // password char[] was cloned in PBEKeySpec constructor,
            // so we can zero it out here
        } finally {
            if (passwdChars != null) Arrays.fill(passwdChars, '\0');
            if (passwdBytes != null) Arrays.fill(passwdBytes, (byte)0x00);
        }

        SecretKey s;
        try {
            s = kdf.generateSecret(pbeSpec);

        } catch (InvalidKeySpecException ikse) {
            InvalidKeyException ike =
                    new InvalidKeyException("Cannot construct PBE key");
            ike.initCause(ikse);
            throw ike;
        }
        byte[] derivedKey = s.getEncoded();
        SecretKeySpec cipherKey = new SecretKeySpec(derivedKey, cipherAlgo);

        // initialize the underlying cipher
        cipher.init(opmode, cipherKey, ivSpec, random);
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec pbeSpec = null;
        if (params != null) {
            try {
                pbeSpec = params.getParameterSpec(PBEParameterSpec.class);
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException(
                    "Wrong parameter type: PBE expected");
            }
        }
        engineInit(opmode, key, pbeSpec, random);
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if ((inputLen == 0) || (input == null)) {
            return B0;
        }
        return cipher.update(input, inputOffset, inputLen);
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
        throws ShortBufferException {
        if ((inputLen == 0) || (input == null)) {
            return 0;
        }
        return cipher.update(input, inputOffset, inputLen,
                             output, outputOffset);
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException {
        if ((inputLen == 0) || (input == null)) {
            return cipher.doFinal();
        }
        return cipher.doFinal(input, inputOffset, inputLen);
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {
        if ((inputLen == 0) || (input == null)) {
            byte[] result = cipher.doFinal();
            int length = result.length;
            if (outputOffset + length > output.length) {
                throw new IllegalArgumentException("Bad arguments");
            }
            System.arraycopy(result, 0, output, outputOffset, length);
            return length;
        }
        return cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        return keyLength;
    }

    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException {
        return cipher.wrap(key);
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
                               int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException {
        return cipher.unwrap(wrappedKey, wrappedKeyAlgorithm,
                             wrappedKeyType);
    }

    public static final class HmacSM3AndSM4_128_CBC_PKCS5Padding extends PBES2Core {
        public HmacSM3AndSM4_128_CBC_PKCS5Padding()
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSM3", "SM4", 16, "CBC", "PKCS5Padding");
        }
    }

    public static final class HmacSM3AndSM4_128_ECB_PKCS5Padding extends PBES2Core {
        public HmacSM3AndSM4_128_ECB_PKCS5Padding()
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSM3", "SM4", 16, "ECB", "PKCS5Padding");
        }
    }
}
