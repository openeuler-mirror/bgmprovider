package org.openeuler.sdf.wrapper;

import org.openeuler.sdf.commons.exception.SDFException;

public class SDFRSAKeyPairGeneratorNative {
    public native static byte[][] nativeGenerateKeyPair(long sessionHandleAddr, byte[] kekId, byte[] regionId,
                                                        byte[] cdpId, byte[] pin, int keySize) throws SDFException;
}
