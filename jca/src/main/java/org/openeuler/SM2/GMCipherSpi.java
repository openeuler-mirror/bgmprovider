/*
 * Copyright (c) 2022, Huawei Technologies Co., Ltd. All rights reserved.
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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.openeuler.util.*;


public class GMCipherSpi
        extends CipherSpi
{

    private SM2Engine engine;
    private int state = -1;
    private ErasableOutputStream buffer = new ErasableOutputStream();
    private ECKeyParameters key;
    private SecureRandom random;

    public GMCipherSpi(SM2Engine engine)
    {
        this.engine = engine;
    }

    public int engineGetBlockSize()
    {
        return 0;
    }

    public int engineGetKeySize(Key key)
    {
        if (key instanceof ECKey)
        {
            return ((ECKey)key).getParams().getCurve().getField().getFieldSize();
        }
        else
        {
            throw new IllegalArgumentException("not an EC key");
        }
    }


    public byte[] engineGetIV()
    {
        return null;
    }

    public AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    public void engineSetMode(String mode)
            throws NoSuchAlgorithmException
    {
        String modeName = Util.toUpperCase(mode);

        if (!modeName.equals("NONE"))
        {
            throw new IllegalArgumentException("can't support mode " + mode);
        }
    }

    public int engineGetOutputSize(int inputLen)
    {
        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
        {
            return engine.getOutputSize(inputLen);
        }
        else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
        {
            return engine.getOutputSize(inputLen);
        }
        else
        {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    public void engineSetPadding(String padding)
            throws NoSuchPaddingException
    {
        String paddingName = Util.toUpperCase(padding);

        // TDOD: make this meaningful...
        if (!paddingName.equals("NOPADDING"))
        {
            throw new NoSuchPaddingException("padding not available with IESCipher");
        }
    }


    // Initialisation methods

    public void engineInit(
            int opmode,
            Key key,
            AlgorithmParameters params,
            SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (params != null)
        {
            throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + params.getClass().getName());
        }

        engineInit(opmode, key, paramSpec, random);
    }

    public void engineInit(
            int opmode,
            Key key,
            AlgorithmParameterSpec engineSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        // Parse the recipient's key
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)
        {
            if (key instanceof BGECPublicKey)
            {
                this.key = ((BGECPublicKey) key).getKeyParameters();
            } else if (key instanceof ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) key;
                ECParameterSpec ecParameterSpec = ecPublicKey.getParams();
                this.key = new ECPublicKeyParameters(ecPublicKey.getW(),
                        new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getGenerator(),
                                ecParameterSpec.getOrder(), BigInteger.valueOf(ecParameterSpec.getCofactor())));
            }
            else
            {
                throw new InvalidKeyException("must be passed public SM2 key for encryption");
            }
        }
        else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof BGECPrivateKey)
            {
                this.key = ((BGECPrivateKey)key).getKeyParameters();
            } else if (key instanceof ECPrivateKey) {
                ECPrivateKey ecPrivateKey = (ECPrivateKey) key;
                ECParameterSpec ecParameterSpec = ecPrivateKey.getParams();
                this.key = new ECPrivateKeyParameters(ecPrivateKey.getS(),
                        new ECDomainParameters(ecParameterSpec.getCurve(), ecParameterSpec.getGenerator(),
                                ecParameterSpec.getOrder(), BigInteger.valueOf(ecParameterSpec.getCofactor())));
            }
            else
            {
                throw new InvalidKeyException("must be passed private EC key for decryption");
            }
        }
        else
        {
            throw new InvalidKeyException("must be passed EC key");
        }


        if (random != null)
        {
            this.random = random;
        }
        else
        {
            this.random = new SecureRandom();
        }

        this.state = opmode;
        buffer.reset();
    }

    public void engineInit(
            int opmode,
            Key key,
            SecureRandom random)
            throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new IllegalArgumentException("cannot handle supplied parameter spec: " + e.getMessage());
        }
    }


    // Update methods - buffer the input

    public byte[] engineUpdate(
            byte[] input,
            int inputOffset,
            int inputLen)
    {
        buffer.write(input, inputOffset, inputLen);
        return null;
    }


    public int engineUpdate(
            byte[] input,
            int inputOffset,
            int inputLen,
            byte[] output,
            int outputOffset)
    {
        buffer.write(input, inputOffset, inputLen);
        return 0;
    }


    // Finalisation methods

    public byte[] engineDoFinal(
            byte[] input,
            int inputOffset,
            int inputLen)
            throws IllegalBlockSizeException, BadPaddingException
    {
        if (inputLen != 0)
        {
            buffer.write(input, inputOffset, inputLen);
        }

        try
        {
            if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
            {
                // Encrypt the buffer
                try
                {
                    engine.init(true, key);

                    return engine.processBlock(buffer.getBuf(), 0, buffer.size());
                }
                catch (final Exception e)
                {
                    throw new BadBlockException("unable to process block", e);
                }
            }
            else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
            {
                // Decrypt the buffer
                try
                {
                    engine.init(false, key);

                    return engine.processBlock(buffer.getBuf(), 0, buffer.size());
                }
                catch (final Exception e)
                {
                    throw new BadBlockException("unable to process block", e);
                }
            }
            else
            {
                throw new IllegalStateException("cipher not initialised");
            }
        }
        finally
        {
            buffer.erase();
        }
    }

    public int engineDoFinal(
            byte[] input,
            int inputOffset,
            int inputLength,
            byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] buf = engineDoFinal(input, inputOffset, inputLength);
        System.arraycopy(buf, 0, output, outputOffset, buf.length);
        return buf.length;
    }

    protected static final class ErasableOutputStream
            extends ByteArrayOutputStream
    {
        public ErasableOutputStream()
        {
        }

        public byte[] getBuf()
        {
            return buf;
        }

        public void erase()
        {
            java.util.Arrays.fill(this.buf, (byte)0);
            reset();
        }
    }
}

