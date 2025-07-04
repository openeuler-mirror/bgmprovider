package org.openeuler.sdf.jca.symmetric;

import java.security.InvalidParameterException;

public class SDFSM7KeyGenerator extends SDFKeyGeneratorCore {
    private static final int DEFAULT_KEY_SIZE = 128;

    public SDFSM7KeyGenerator() {
        super("SM7", DEFAULT_KEY_SIZE);
    }

    @Override
    protected void checkKey(int keysize) {
        if (keysize != DEFAULT_KEY_SIZE) {
            throw new InvalidParameterException("SM7 requires a 128 bit key");
        }
    }
}
