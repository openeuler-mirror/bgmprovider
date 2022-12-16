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
        return cipher.engineDoFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return cipher.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        cipher.engineUpdateAAD(src, offset, len);
    }
}
