package org.openeuler.org.bouncycastle;

import java.io.IOException;

/**
 * this exception is thrown whenever we find something we don't expect in a
 * message.
 */
public class InvalidCipherTextException
        extends java.lang.Exception
{
    /**
     * base constructor.
     */
    public InvalidCipherTextException()
    {
    }

    /**
     * create a InvalidCipherTextException with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public InvalidCipherTextException(
            String  message)
    {
        super(message);
    }

    public InvalidCipherTextException(String derSequence_getEncoded_failed, IOException e) {
    }
}

