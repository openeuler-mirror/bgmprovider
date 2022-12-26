package org.openeuler.sm4;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class SM4ParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private SecureRandom random;
    private AlgorithmParameterSpec param;
    private AlgorithmParameters parameters;
    @Override
    protected void engineInit(int size, SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random) throws InvalidAlgorithmParameterException {
        if(genParamSpec.getClass().equals(IvParameterSpec.class)){
            param = genParamSpec;
        }else if(genParamSpec.getClass().equals(GCMParameterSpec.class)){
            param =genParamSpec;
        }else {
            throw new InvalidAlgorithmParameterException();
        }
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        try {
            parameters = AlgorithmParameters.getInstance("SM4");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
       if(param==null){
            byte[] iv = new byte[16];
            if(this.random==null){
                random = new SecureRandom();
            }
            random.nextBytes(iv);
            param = new IvParameterSpec(iv);
            try {
                parameters.init(param);
            } catch (InvalidParameterSpecException e) {
                e.printStackTrace();
            }
        }
        try {
            parameters.init(param);
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        }
        return parameters;
    }
}
