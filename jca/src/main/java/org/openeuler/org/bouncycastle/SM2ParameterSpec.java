package org.openeuler.org.bouncycastle;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * Parameter spec for SM2 ID parameter
 */
public class SM2ParameterSpec implements AlgorithmParameterSpec {
    private byte[] id;

    private ECParameterSpec params;

    /**
     * Return the ID value.
     *
     * @return the ID string.
     */
    public byte[] getId() {
        return id == null ? null : id.clone();
    }

    public ECParameterSpec getParams() {
        return params;
    }

    /**
     * Base constructor.
     *
     * @param id the ID string associated with this usage of SM2.
     */
    public SM2ParameterSpec(byte[] id) {
        this(id, null);
    }

    public SM2ParameterSpec(byte[] id, ECParameterSpec params) {
        if (id == null) {
            throw new NullPointerException("id string cannot be null");
        }
        this.id = id;
        this.params = params;
    }
}
