package org.openeuler.sm4;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class SM4Parameters extends AlgorithmParametersSpi {

    private byte[] iv;
    private GCMParameterSpec gcmParameterSpec;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if(paramSpec==null){
            throw new InvalidParameterSpecException();
        }else{
            if(!(paramSpec instanceof GCMParameterSpec)){
                if (!(paramSpec instanceof IvParameterSpec)) {
                    throw new InvalidParameterSpecException();
                } else {
                    this.iv = ((IvParameterSpec) paramSpec).getIV();
                }
            }else {
                this.gcmParameterSpec = (GCMParameterSpec) paramSpec;
            }
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException();
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
            throw new IOException();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if(paramSpec!=GCMParameterSpec.class){
            if(paramSpec!=IvParameterSpec.class){
                throw new InvalidParameterSpecException();
            }else {
                return (T) new IvParameterSpec(this.iv);
            }
        }else{
         return (T) gcmParameterSpec;
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException();
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw  new IOException();
    }

    @Override
    protected String engineToString() {
        return "SM4 Parameters";
    }
}
