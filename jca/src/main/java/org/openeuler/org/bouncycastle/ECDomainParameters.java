package org.openeuler.org.bouncycastle;

import org.openeuler.sun.security.util.ECNamedCurve;
import org.openeuler.util.Util;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;


public class ECDomainParameters
{
    private final EllipticCurve curve;
    private final byte[]      seed;
    private final ECPoint G;
    private final BigInteger  n;
    private final BigInteger  h;

    private BigInteger  hInv = null;

    public ECDomainParameters(ECNamedCurve x)
    {
        this(x.getCurve(), x.getGenerator(), x.getOrder(), BigInteger.valueOf(x.getCofactor()));
    }

    public ECDomainParameters(
            EllipticCurve     curve,
            ECPoint     G,
            BigInteger  n)
    {
        this(curve, G, n, Util.ONE, null);
    }

    public ECDomainParameters(
            EllipticCurve     curve,
            ECPoint     G,
            BigInteger  n,
            BigInteger  h)
    {
        this(curve, G, n, h, null);
    }

    public ECDomainParameters(
            EllipticCurve     curve,
            ECPoint     G,
            BigInteger  n,
            BigInteger  h,
            byte[]      seed)
    {
        if (curve == null)
        {
            throw new NullPointerException("curve");
        }
        if (n == null)
        {
            throw new NullPointerException("n");
        }

        this.curve = curve;
        this.G = validatePublicPoint(curve, G);
        this.n = n;
        this.h = h;
        this.seed = null == seed ? null:seed.clone();
    }

    public EllipticCurve getCurve()
    {
        return curve;
    }

    public ECPoint getG()
    {
        return G;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public synchronized BigInteger getHInv()
    {
        if (hInv == null)
        {
            hInv = h.modInverse(n);
        }
        return hInv;
    }

    public byte[] getSeed()
    {
        return null == seed ? null:seed.clone();
    }

    public boolean equals(
            Object  obj)
    {
        if (this == obj)
        {
            return true;
        }

        if (!(obj instanceof ECDomainParameters))
        {
            return false;
        }

        ECDomainParameters other = (ECDomainParameters)obj;

        return this.curve.equals(other.curve)
                && this.G.equals(other.G)
                && this.n.equals(other.n);
    }

    public int hashCode()
    {
//        return Arrays.hashCode(new Object[]{ curve, G, n });
        int hc = 4;
        hc *= 257;
        hc ^= curve.hashCode();
        hc *= 257;
        hc ^= G.hashCode();
        hc *= 257;
        hc ^= n.hashCode();
        return hc;
    }

    public BigInteger validatePrivateScalar(BigInteger d)
    {
        if (null == d)
        {
            throw new NullPointerException("Scalar cannot be null");
        }

        if (d.compareTo(Util.ONE) < 0  || (d.compareTo(getN()) >= 0))
        {
            throw new IllegalArgumentException("Scalar is not in the interval [1, n - 1]");
        }

        return d;
    }

    public ECPoint validatePublicPoint(ECPoint q)
    {
        return validatePublicPoint(getCurve(), q);
    }

    static ECPoint validatePublicPoint(EllipticCurve c, ECPoint q)
    {
        if (null == q)
        {
            throw new NullPointerException("Point cannot be null");
        }

        if (q.equals(ECPoint.POINT_INFINITY))
        {
            throw new IllegalArgumentException("Point at infinity");
        }

        BigInteger p = ((ECFieldFp) c.getField()).getP();
        BigInteger a = c.getA(), b = c.getB();
        BigInteger x = q.getAffineX(), y = q.getAffineY();

        if ( !(y.pow(2).mod(p).equals((x.pow(3).add(a.multiply(x)).add(b)).mod(p))) )
        {
            throw new IllegalArgumentException("Point not on curve");
        }

        return q;
    }
}
