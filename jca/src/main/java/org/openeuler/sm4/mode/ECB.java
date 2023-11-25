package org.openeuler.sm4.mode;

import org.openeuler.sm4.SM4BaseCipher;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * SM4 ECB mode
 */
public class ECB extends SM4BaseCipher {
    @Override
    public void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        init(opmode, key);
        isInitialized = true;
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("ECB mode cannot use an AlgorithmParameterSpec");
        }
        engineInit(opmode, key, random);
    }

    @Override
    public void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("ECB mode cannot use an AlgorithmParameters");
        }
        engineInit(opmode, key, random);
    }


    @Override
    public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        if (input == null || inputLen == 0) {
            return null;
        }
        //record input data
        inputUpdate = input;
        inputLenUpdate = inputLen;
        inputOffsetUpdate = inputOffset;

        byte[] res = null;
        //determine the length of data processed by the update method
        if (padding.getPadding().toUpperCase().equals("NOPADDING")) {
            if (inputLen < 16) {
                len = 0;
                return null;
            } else {
                len = inputLen - (inputLen % 16);
            }
        } else {
            if (inputLen <= 16) {
                len = 0;
                return null;
            } else if (inputLen % 16 == 0) {
                len = inputLen - 16;
            } else {
                len = inputLen - (inputLen % 16);
            }
        }
        res = new byte[len];
        if (opmode == Cipher.ENCRYPT_MODE) {
            for (int i = inputOffset; i + 16 <= len + inputOffset; i += 16) {
                sm4.encrypt(this.rk, input, i, res, i - inputOffset);
            }

        } else if (opmode == Cipher.DECRYPT_MODE) {
            for (int i = inputOffset; i + 16 <= len + inputOffset; i += 16) {
                sm4.decrypt(this.rk, input, i, res, i - inputOffset);
            }
        }
        return res;
    }

    @Override
    public int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        if (input == null || inputLen == 0) {
            return 0;
        }
        inputUpdate = input;
        inputLenUpdate = inputLen;
        inputOffsetUpdate = inputOffset;
        if (padding.getPadding().toUpperCase().equals("NOPADDING")) {
            if (inputLen < 16) {
                len = 0;
                return 0;
            } else {
                len = inputLen - (inputLen % 16);
            }
        } else {
            if (inputLen <= 16) {
                len = 0;
                return 0;
            } else if (inputLen % 16 == 0) {
                len = inputLen - 16;
            } else {
                len = inputLen - (inputLen % 16);
            }
        }
        if (opmode == Cipher.ENCRYPT_MODE) {
            for (int i = inputOffset; i + 16 <= len + inputOffset; i += 16) {
                sm4.encrypt(this.rk, input, i, output, outputOffset + i - inputOffset);
            }

        } else if (opmode == Cipher.DECRYPT_MODE) {
            for (int i = inputOffset; i + 16 <= len + inputOffset; i += 16) {
                sm4.decrypt(this.rk, input, i, output, outputOffset + i - inputOffset);
            }
        }
        return len;
    }


    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        byte[] res = null;
        int restLen = inputLenUpdate - len;//the number of unprocessed bytes in the update method
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            //determine if the input data is valid
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                if ((inputLenUpdate - len + inputLen) % 16 != 0) {
                    throw new IllegalBlockSizeException();
                }
            }
            //determine the number of bytes required to store the encryption result
            int length = engineGetOutputSize(inputLenUpdate - len + inputLen);
            res = new byte[length];
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0);
            } else if (restLen == 16) {
                //encrypt the remaining bytes
                sm4.encrypt(this.rk, inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, res, 0);
                //encrypt input data
                encrypt(input, inputOffset, inputLen, res, 16);
            } else {
                if (16 - restLen > inputLen) {
                    //restLen+inputLen<16
                    //concatenate the remaining lengths with the input data
                    byte[] block = new byte[inputLen + restLen];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, inputLen, block, restLen);
                    byte[] fill = padding.fill(block);
                    sm4.encrypt(this.rk, fill, 0, res, res.length - 16);
                } else {
                    //
                    byte[] block = new byte[16];
                    //concatenate the remaining data and the input data into a  block
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                    //encrypt block
                    sm4.encrypt(this.rk, block, 0, res, 0);
                    //encrypt remaining input data
                    encrypt(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, res, 16);
                }
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            //determine if the input data is valid
            if ((inputLen + inputLenUpdate - len) % 16 != 0) {
                throw new IllegalBlockSizeException();
            }

            if (restLen == 0) {
                if (inputLen == 0) {
                    return res;
                } else {
                    //decrypt the last block to determine the length of the returned result
                    res = decryptLastBlock(input, inputOffset, inputLen, 0);
                    //decrypt the remaining data
                    decrypt(input, inputOffset, inputLen - 16, res, 0);
                }
            } else if (restLen == 16) {
                if (inputLen == 0) {
                    res = decryptLastBlock(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, 0);
                } else {
                    //decrypt the last block to determine the length of the returned result
                    res = decryptLastBlock(input, inputOffset, inputLen, 16);
                    //decrypt the remaining data
                    decrypt(inputUpdate, inputOffsetUpdate + len, 16, res, 0);
                    decrypt(input, inputOffset, inputLen - 16, res, 16);
                }
            } else {
                byte[] block = new byte[16];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                if (inputLen == 16 - restLen) {
                    res = decryptLastBlock(block, 0, 16, 0);
                } else {
                    //decrypt the last block to determine the length of the returned result
                    res = decryptLastBlock(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, 16);
                    //decrypt the remaining data
                    decrypt(block, 0, 16, res, 0);
                    decrypt(input, inputOffset + 16 - restLen, inputLen - 32 + restLen, res, 16);
                }
            }
        }
        this.reset();
        return res;
    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        int need = 0;
        int restLen = inputLenUpdate - len;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                if ((inputLenUpdate - len + inputLen) % 16 != 0) {
                    throw new IllegalBlockSizeException();
                }
            }
            need = engineGetOutputSize(inputLenUpdate - len + inputLen);
            if (outputOffset + need > output.length) {
                throw new ShortBufferException();
            }
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, output, outputOffset);
            } else if (restLen == 16) {
                sm4.encrypt(this.rk, inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, output, outputOffset);
                encrypt(input, inputOffset, inputLen, output, outputOffset + 16);
            } else {
                if (16 - restLen > inputLen) {
                    byte[] block = new byte[inputLen + restLen];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, inputLen, block, restLen);
                    byte[] fill = padding.fill(block);
                    sm4.encrypt(this.rk, fill, 0, output, outputOffset + need - 16);
                } else {
                    byte[] block = new byte[16];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                    sm4.encrypt(this.rk, block, 0, output, outputOffset);
                    encrypt(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, output, outputOffset + 16);
                }
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if ((inputLen + inputLenUpdate - len) % 16 != 0) {
                throw new IllegalBlockSizeException();
            }

            if (restLen == 0) {
                if (inputLen == 0) {
                    return need;
                } else {
                    need = decryptLastBlock(input, inputOffset, inputLen, 0, output, outputOffset);
                    decrypt(input, inputOffset, inputLen - 16, output, outputOffset);
                }
            } else if (restLen == 16) {
                if (inputLen == 0) {
                    need = decryptLastBlock(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, 0, output, outputOffset);
                } else {
                    need = decryptLastBlock(input, inputOffset, inputLen, 16, output, outputOffset);
                    decrypt(inputUpdate, inputOffsetUpdate + len, 16, output, outputOffset);
                    decrypt(input, inputOffset, inputLen - 16, output, outputOffset + 16);
                }
            } else {
                byte[] block = new byte[16];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                if (inputLen == 16 - restLen) {
                    need = decryptLastBlock(block, 0, 16, 0, output, outputOffset);
                } else {
                    need = decryptLastBlock(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, 16, output, outputOffset);
                    decrypt(block, 0, 16, output, outputOffset);
                    decrypt(input, inputOffset + 16 - restLen, inputLen - 32 + restLen, output, outputOffset + 16);
                }
            }
        }
        this.reset();
        return need;
    }

    /**
     * SM4  bulk decryption
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param res
     * @param offset
     * @throws BadPaddingException
     */
    private void decrypt(byte[] input, int inputOffset, int inputLen, byte[] res, int offset) throws BadPaddingException {
        for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
            sm4.decrypt(this.rk, input, i, res, offset + i - inputOffset);
        }
    }

    /**
     * decrypt the last block and return an array containing the decrypted result.
     * if there is padding the length of the final result can only be determined if the last block is decrypted.
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param extra       the number of bytes required in addition to the input data
     * @return byte array which contain the last block decrypted and whose length is extra+inputLen-16+(lastBlockDecrypted).length
     * @throws BadPaddingException
     */
    private byte[] decryptLastBlock(byte[] input, int inputOffset, int inputLen, int extra) throws BadPaddingException {
        byte[] res;
        byte[] last = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
        if (!this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            byte[] recover = padding.recover(last);
            res = new byte[inputLen - 16 + recover.length + extra];
            sm4.copyArray(recover, 0, recover.length, res, res.length - recover.length);
        } else {
            res = new byte[inputLen + extra];
            sm4.copyArray(last, 0, last.length, res, res.length - last.length);
        }
        return res;
    }

    /**
     * decrypting the last block and return  the number of bytes required to store the decryption result
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param extra        the number of bytes required in addition to the input data
     * @param output
     * @param outputOffset
     * @return the number of bytes required to store the decryption result
     * @throws BadPaddingException
     * @throws ShortBufferException
     */
    private int decryptLastBlock(byte[] input, int inputOffset, int inputLen, int extra, byte[] output, int outputOffset) throws BadPaddingException, ShortBufferException {
        byte[] last = sm4.decrypt(this.rk, input, inputOffset + inputLen - 16);
        int need;
        if (!this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            byte[] recover = padding.recover(last);
            need = inputLen - 16 + recover.length + extra;
            if (need + outputOffset > output.length) {
                throw new ShortBufferException();
            }
            sm4.copyArray(recover, 0, recover.length, output, outputOffset + need - recover.length);
        } else {
            need = inputLen + extra;
            if (need + outputOffset > output.length) {
                throw new ShortBufferException();
            }
            sm4.copyArray(last, 0, last.length, output, outputOffset + need - last.length);
        }
        return need;
    }

    /**
     * ECB encrypt
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param res         byte array to store the encryption result
     * @param offset
     */
    private void encrypt(byte[] input, int inputOffset, int inputLen, byte[] res, int offset) {
        int i;
        for (i = inputOffset; i + 16 <= inputOffset + inputLen; i += 16) {
            sm4.encrypt(this.rk, input, i, res, offset + (i - inputOffset));
        }
        if (inputLen % 16 != 0) {
            byte[] fill = padding.fill(input, i, inputLen % 16);
            sm4.encrypt(this.rk, fill, 0, res, offset + (i - inputOffset));
        }
        if (inputLen % 16 == 0 && !padding.getPadding().equals("NOPADDING")) {
            byte[] block = new byte[BLOCKSIZE];
            Arrays.fill(block, (byte) 16);
            sm4.encrypt(this.rk, block, 0, res, offset + i - inputOffset);
        }
    }

}
