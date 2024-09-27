package org.openeuler.sdf.jca.symmetric;

import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class SDFSM7Parameters extends AlgorithmParametersSpi {
    private byte[] iv = null;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        byte[] tmpIv = ((IvParameterSpec)paramSpec).getIV();
        iv = tmpIv.clone();
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
        if (IvParameterSpec.class.isAssignableFrom(paramSpec)) {
            return paramSpec.cast(new IvParameterSpec(this.iv));
        } else {
            throw new InvalidParameterSpecException
                    ("Inappropriate parameter specification");
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
        return "SM7 Parameters";
    }
}
