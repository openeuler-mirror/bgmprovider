package org.openeuler.org.bouncycastle;

import javax.crypto.BadPaddingException;

public class BadBlockException
        extends BadPaddingException
{
    private final Throwable cause;

    public BadBlockException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}

