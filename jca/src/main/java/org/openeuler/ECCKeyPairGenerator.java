package org.openeuler;

import org.openeuler.SM2.BGECPrivateKey;
import org.openeuler.SM2.BGECPublicKey;
import org.openeuler.util.ECUtil;
import sun.security.ec.ECKeyPairGenerator;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Optional;

public class ECCKeyPairGenerator extends java.security.KeyPairGeneratorSpi {

    // used to seed the keypair generator
    private SecureRandom random;

    // parameters specified via init, if any
    private AlgorithmParameterSpec params = null;

    KeyPairGeneratorSpi engine = new ECKeyPairGenerator();

    private boolean isInitialized = false;

    public ECCKeyPairGenerator() {
        initialize(256, null);
    }

    /**
     * Initializes the key pair generator for a certain keysize, using
     * the default parameter set.
     *
     * @param keysize the keysize. This is an
     *                algorithm-specific metric, such as modulus length, specified in
     *                number of bits.
     * @param random  the source of randomness for this generator.
     * @throws InvalidParameterException if the {@code keysize} is not
     *                                   supported by this KeyPairGeneratorSpi object.
     */
    @Override
    public void initialize(int keysize, SecureRandom random) {

        initialize(keysize, random);
        isInitialized = true;
    }

    // second initialize method. See JCA doc
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        engine.initialize(params, random);
        isInitialized = true;
    }


    /**
     * Generates a key pair. Unless an initialization method is called
     * using a KeyPairGenerator interface, algorithm-specific defaults
     * will be used. This will generate a new key pair every time it
     * is called.
     *
     * @return the newly generated {@code KeyPair}
     */
    @Override
    public KeyPair generateKeyPair() {
        if (!isInitialized) {
            initialize(256, new SecureRandom());
        }
        KeyPair keyPair = engine.generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        ECParameterSpec ecParams = publicKey.getParams();
        try {
            PrivateKey bgPrivateKey = new BGECPrivateKey(privateKey.getS(), ecParams);
            PublicKey bgPublicKey = new BGECPublicKey(publicKey.getW(), ecParams);
            return new KeyPair(bgPublicKey, bgPrivateKey);
        } catch (InvalidKeyException e) {
            throw new ProviderException(e);
        }
    }
}
