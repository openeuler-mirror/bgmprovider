package org.openeuler.org.bouncycastle;

public class AsymmetricKeyParameter
        implements CipherParameters
{
    boolean privateKey;

    public AsymmetricKeyParameter(
            boolean privateKey)
    {
        this.privateKey = privateKey;
    }

    public boolean isPrivate()
    {
        return privateKey;
    }
}

