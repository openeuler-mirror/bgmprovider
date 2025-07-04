package org.openeuler.sdf.jca.asymmetric.sun.security.sm9;

import org.openeuler.sdf.jca.asymmetric.SDFSM9ParameterSpec;

import java.security.*;
import java.security.spec.*;

public class SDFSM9KeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        return implGeneratePublic(keySpec);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        return implGeneratePrivate(keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key instanceof PublicKey) {
            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
            if (keySpec.isAssignableFrom(SDFSM9ParameterSpec.class)) {
                return keySpec.cast(new SDFSM9PublicKey(key.getEncoded()));
            }
        }

        if (key instanceof PrivateKey) {
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            if (keySpec.isAssignableFrom(SDFSM9ParameterSpec.class)) {
                return keySpec.cast(new SDFSM9UserPrivateKey(key.getEncoded()));
            }
        }
        throw new InvalidKeySpecException("keySpec not support.");
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        return key;
    }

    private PublicKey implGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            X509EncodedKeySpec spec = (X509EncodedKeySpec) keySpec;
            return new SDFSM9PublicKey(spec.getEncoded());
        } else {
            throw new InvalidKeySpecException("Only SDFSM9ParameterSpec supported for public keys");
        }
    }

    private PrivateKey implGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            X509EncodedKeySpec spec = (X509EncodedKeySpec) keySpec;
            return new SDFSM9UserPrivateKey(spec.getEncoded());
        } else {
            throw new InvalidKeySpecException("Only SDFSM9ParameterSpec supported for private keys");
        }
    }
}
