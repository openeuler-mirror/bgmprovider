package org.openeuler;


import java.math.BigInteger;
import java.security.spec.ECPoint;

public class SM2Point extends ECPoint {

    private volatile SM2PreComputeInfo preComputeInfo;

    public SM2PreComputeInfo getPreComputeInfo() {
        return preComputeInfo;
    }

    public void setPreComputeInfo(SM2PreComputeInfo preComputeInfo) {
        this.preComputeInfo = preComputeInfo;
    }

    public SM2Point(BigInteger x, BigInteger y) {
        super(x, y);
    }

    public SM2Point(BigInteger x, BigInteger y, SM2PreComputeInfo preComputeInfo) {
        super(x, y);
        this.preComputeInfo = preComputeInfo;
    }

    public SM2Point(ECPoint ecPoint) {
        this(ecPoint.getAffineX(), ecPoint.getAffineY());
    }
}
