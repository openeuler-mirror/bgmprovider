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

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SM4BaseCipher extends CipherSpi {
    protected boolean isInitialized = false;
    protected final int BLOCKSIZE = 16;
    protected int opmode ;//default
    protected SM4Padding padding = new SM4Padding();//default
    protected SM4Util sm4 = new SM4Util();
    protected  byte[] inputUpdate;//save the input parameter in the update method
    protected int inputLenUpdate;//save the inputLen parameter in the update method
    protected int inputOffsetUpdate;//save the inputoffSet parameter in the update method
    protected int len;//the actual size of the data processed in the update method
    protected int[] rk;

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        super.engineUpdateAAD(src, offset, len);
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException();
    }

    @Override
    public void engineSetPadding(String padding) throws NoSuchPaddingException {
        this.padding.setPadding(padding);
    }

    @Override
    protected int engineGetBlockSize() {
        return BLOCKSIZE;
    }

    @Override
    public int engineGetOutputSize(int inputLen) {
        if(this.opmode==Cipher.ENCRYPT_MODE){
            if(!this.padding.getPadding().equalsIgnoreCase("NOPADDING")){
                    return inputLen+(16-inputLen%16);
            }else {
                if(inputLen%16!=0){
                    return 0;
                }else {
                    return inputLen;
                }
            }
        }else if(this.opmode == Cipher.DECRYPT_MODE){
            if(inputLen%16!=0){
                return 0;
            }else {
                return inputLen;
            }
        }else {
            return 0;
        }
    }

    @Override
    public byte[] engineGetIV() {
        return null;
    }

    @Override
    public AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    public void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        init(opmode, key);
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(opmode, key);
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(opmode, key);
    }

    protected void init(int opmode, Key key) throws InvalidKeyException {
        if (!(key instanceof SecretKey) || key.getEncoded().length != 16) {
            throw new InvalidKeyException();
        }
        this.opmode = opmode;
        this.rk = sm4.expandKey(key.getEncoded());
    }

    @Override
    public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return null;
    }

    @Override
    public int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        return 0;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return null;
    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }

    /**
     * reset some parameters after encryption
     */
    public void reset(){
        inputUpdate=null;
        inputLenUpdate=0;
        len = 0;
    }

}
