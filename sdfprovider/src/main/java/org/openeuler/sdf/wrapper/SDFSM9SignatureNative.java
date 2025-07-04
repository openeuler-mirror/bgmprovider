package org.openeuler.sdf.wrapper;

public class SDFSM9SignatureNative {
    /**
     * SM9 sign
     *
     * @param masterPubKeyArr sign master public key
     * @param userPrivateKeyArr user sign private key in bytes
     * @param data sign data
     * @param pairG speed up param
     * @return sm9 signature data
     */
    public static native byte[] nativeSM9Sign(byte[] masterPubKeyArr, byte[] userPrivateKeyArr,
                                              byte[] data, byte[] pairG);

    /**
     * SM9 verify
     *
     * @param masterPubKeyArr sign master public key
     * @param signatureArr signature
     * @param data sign verify data
     * @param pairG speed up param
     * @param hId hId
     * @param userId userId
     * @return true if the signature was verified, false if not.
     */
    public static native boolean nativeSM9Verify(byte[] masterPubKeyArr, byte[] signatureArr, byte[] data,
                                                 byte[] pairG, byte[] hId, byte[] userId);
}
