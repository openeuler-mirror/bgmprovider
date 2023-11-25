package org.openeuler.sm4.mode;

import org.openeuler.sm4.StreamModeBaseCipher;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.util.Arrays;

/**
 * SM4 OFB mode
 */
public class OFB extends StreamModeBaseCipher {
    @Override
    public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        if (input == null || inputLen == 0) {
            return null;
        }
        inputUpdate = input;
        inputLenUpdate = inputLen;
        inputOffsetUpdate = inputOffset;
        byte[] res = null;
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
        processOFB(input, inputOffset, len, res, 0);
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
        if (outputOffset + len > output.length) {
            throw new ShortBufferException();
        }
        processOFB(input, inputOffset, len, output, outputOffset);
        return len;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(!isInitialized){
            throw new IllegalStateException("cipher uninitialized");
        }
        byte[] res = null;
        int restLen = inputLenUpdate - len;
        if (this.opmode == Cipher.ENCRYPT_MODE) {
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                if ((inputLenUpdate - len + inputLen) % 16 != 0) {
                    throw new IllegalBlockSizeException();
                }
            }
            int length = engineGetOutputSize(inputLenUpdate - len + inputLen);
            res = new byte[length];
            if (restLen == 0) {
                encrypt(input, inputOffset, inputLen, res, 0);
            } else if (restLen == 16) {
                processOFB(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, res, 0);
                encrypt(input, inputOffset, inputLen, res, 16);
            } else {
                if (16 - restLen > inputLen) {
                    byte[] block = new byte[inputLen + restLen];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, inputLen, block, restLen);
                    encrypt(block, 0, block.length, res, 0);
                } else {
                    byte[] block = new byte[16];
                    sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                    sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                    processOFB(block, 0, 16, res, 0);
                    encrypt(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, res, 16);
                }
            }
        } else if (this.opmode == Cipher.DECRYPT_MODE) {
            if ((inputLen + inputLenUpdate - len) % 16 != 0) {
                throw new IllegalBlockSizeException();
            }
            byte[] tem = new byte[inputLen + inputLenUpdate - len];
            if (restLen == 0) {
                if (inputLen == 0) {
                    this.reset();
                    return res;
                } else {
                    processOFB(input, inputOffset, inputLen, tem, 0);
                }
            } else if (restLen == 16) {
                if (inputLen == 0) {
                    processOFB(inputUpdate, inputOffsetUpdate + inputLenUpdate - 16, 16, tem, 0);
                } else {
                    processOFB(inputUpdate, inputOffsetUpdate + len, 16, tem, 0);
                    processOFB(input, inputOffset, inputLen, tem, 16);
                }
            } else {
                byte[] block = new byte[16];
                sm4.copyArray(inputUpdate, inputOffsetUpdate + len, restLen, block, 0);
                sm4.copyArray(input, inputOffset, 16 - restLen, block, restLen);
                if (inputLen == 16 - restLen) {
                    processOFB(block, 0, 16, tem, 0);
                } else {
                    processOFB(block, 0, 16, tem, 0);
                    processOFB(input, inputOffset + 16 - restLen, inputLen - 16 + restLen, tem, 16);
                }
            }
            if (this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
                res = tem;
            } else {
                res = this.padding.recover(tem);
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
        byte[] bytes = engineDoFinal(input, inputOffset, inputLen);
        if (bytes != null) {
            if (outputOffset + bytes.length > output.length) {
                throw new ShortBufferException("buffer is too short.");
            } else {
                sm4.copyArray(bytes, 0, bytes.length, output, outputOffset);
            }
            return bytes.length;
        } else {
            return 0;
        }
    }


    /**
     * encrypt(decrypt) entire blocks of data
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void processOFB(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        for (int i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
            counter = sm4.encrypt(this.rk, counter, 0);
            byte[] xor = sm4.xor(counter, 0, 16, input, i, 16);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
        }
    }

    /**
     * encrypt with handling padding
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     */
    private void encrypt(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        int i;
        for (i = inputOffset; i + 16 <= inputLen + inputOffset; i += 16) {
            counter = sm4.encrypt(this.rk, counter, 0);
            byte[] xor = sm4.xor(counter, 0, 16, input, i, 16);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
        }
        if (inputLen % 16 != 0) {
            byte[] fill = this.padding.fill(input, i, inputLen % 16);
            counter = sm4.encrypt(this.rk, counter, 0);
            byte[] xor = sm4.xor(counter, fill);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
        }

        if (inputLen % 16 == 0 && !this.padding.getPadding().toUpperCase().equals("NOPADDING")) {
            byte[] block = new byte[16];
            Arrays.fill(block, (byte) 16);
            counter = sm4.encrypt(this.rk, counter, 0);
            byte[] xor = sm4.xor(counter, block);
            sm4.copyArray(xor, 0, xor.length, output, outputOffset + i - inputOffset);
        }
    }
}
