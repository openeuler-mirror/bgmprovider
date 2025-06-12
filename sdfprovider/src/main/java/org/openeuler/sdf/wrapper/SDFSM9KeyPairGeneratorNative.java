package org.openeuler.sdf.wrapper;

import org.openeuler.sdf.commons.exception.SDFException;

public class SDFSM9KeyPairGeneratorNative {
    /**
     * generate sign or enc key pair
     *
     * @param outKeyType output key type: sign or enc
     * @param kekId kek id
     * @param regionId region id
     * @param cdpId cdp id
     * @param pin pin
     * @return key pair
     *      {
     *          publicKey
     *          privateKey
     *          pairG
     *      }
     * @throws SDFException SDFException
     */
    public native static byte[][] nativeGenerateKeyPair(int outKeyType, byte[] kekId, byte[] regionId,
                                                        byte[] cdpId, byte[] pin) throws SDFException;

    /**
     * create sign or enc user private key
     *
     * @param outKeyType output key type: sign or enc
     * @param priKey sign or enc master private key
     * @param hId hid
     * @param userId user id
     * @return user private key
     */
    public native static byte[] nativeCreateUserPriKey(int outKeyType, byte[] priKey, byte[] hId, byte[] userId);
}
