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

package org.openeuler.sm4;

import org.openeuler.sm4.mode.*;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * distribution of mode
 */
public class SM4Cipher extends CipherSpi {

    private SM4BaseCipher cipher;

    private final int BLOCK_SIZE = 16;

    abstract static class OidImpl extends SM4Cipher {
        protected OidImpl(String mode, String padding) {
            try {
                engineSetMode(mode);
                engineSetPadding(padding);
            } catch (GeneralSecurityException gse) {
                // internal error; re-throw as provider exception
                ProviderException pe =new ProviderException("Internal Error");
                pe.initCause(gse);
                throw pe;
            }
        }
    }

    public static final class SM4_OCB_NoPadding extends OidImpl {
        public SM4_OCB_NoPadding() {
            super("OCB","NoPadding");
        }
    }


    public static final class SM4_CCM_NoPadding extends OidImpl {
        public SM4_CCM_NoPadding() {
            super("CCM","NoPadding");
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        String upperMode = mode.toUpperCase();
        if("ECB".equals(upperMode)){
              cipher = new ECB();
          }else if("CBC".equals(upperMode)){
              cipher = new CBC();
          }else if("CTR".equals(upperMode)){
            cipher = new CTR();
          }else if("CFB".equals(upperMode)){
            cipher = new CFB();
          }else if("OFB".equals(upperMode)){
            cipher = new OFB();
          }else if("OCB".equals(upperMode)){
            cipher = new OCB();
          }else if("CTS".equals(upperMode)){
            cipher = new CTS();
          }else if("GCM".equals(upperMode)){
            cipher = new GCM();
          }else if("CCM".equals(upperMode)){
           cipher = new CCM();
        } else {
              throw new NoSuchAlgorithmException("unknow mode: "+mode);
          }

    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if("PKCS5Padding".toUpperCase().equals(padding.toUpperCase())){
            cipher.engineSetPadding(padding.toUpperCase());
        }else if("PKCS7Padding".toUpperCase().equals(padding.toUpperCase())){
            cipher.engineSetPadding(padding.toUpperCase());
        }else if("nopadding".toUpperCase().equals(padding.toUpperCase())){
            cipher.engineSetPadding(padding.toUpperCase());
        } else {
            throw new NoSuchPaddingException("unknow padding: "+padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return cipher.engineGetOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
        return cipher.engineGetIV();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return cipher.engineGetParameters();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        cipher.engineInit(opmode,key,random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.engineInit(opmode, key, params, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return cipher.engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return cipher.engineUpdate(input,inputOffset,inputLen,output,outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if (input == null) {
            input = new byte[0];
        }
        return cipher.engineDoFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if (input == null) {
            input = new byte[0];
        }
        return cipher.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        cipher.engineUpdateAAD(src, offset, len);
    }
}
