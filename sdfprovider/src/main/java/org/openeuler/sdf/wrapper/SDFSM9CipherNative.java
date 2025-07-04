package org.openeuler.sdf.wrapper;

import org.openeuler.sdf.commons.exception.SDFException;

public class SDFSM9CipherNative {
    /**
     * @param pubKeyArr public key x, y
     * @param input plain data
     * @param encMode sm9 enc mode
     * @param hIdArr hid
     * @param userIdArr userId
     * @param pariGArr pairG
     * @return enc data
     */
    public static native byte[] nativeSM9Encrypt(byte[] pubKeyArr, byte[] input, int encMode, byte[] hIdArr,
                                                 byte[] userIdArr, byte[] pariGArr) throws SDFException;

    /**
     * @param priKeyArr private key
     * @param cipher enc data
     * @param encMode sm9 enc mode
     * @param userIdArr userId
     * @param pariGArr pairG
     * @return plain data
     */
    public static native byte[] nativeSM9Decrypt(byte[] priKeyArr, byte[] cipher, int encMode, byte[] userIdArr,
                                                 byte[] pariGArr) throws SDFException;
}
