/*
 * Copyright (C) 2005-2007 Robey Pointer <robey@lag.net>
 *
 * This file is part of jaramiko.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package net.lag.crai;

import java.math.BigInteger;


/**
 * Abstract representation for a private key (of type RSA or DSA).  Objects
 * of this type can be used to sign data and retrieve the underlying key
 * contents.
 */
public interface CraiPublicKey
{
    /**
     * Base interface for classes containing the public contents of a key.
     */
    public static interface Contents
    {
        // nothing
    }


    /**
     * The public contents of an RSA key.
     */
    public static interface RSAContents
        extends Contents
    {
        public BigInteger getN();
        public BigInteger getE();
    }


    /**
     * The public contents of a DSA key.
     */
    public static interface DSAContents
        extends Contents
    {
        public BigInteger getP();
        public BigInteger getQ();
        public BigInteger getG();
        public BigInteger getY();
    }


    /**
     * Verify that a signature of a block of data actually came from this
     * key.
     *
     * @param data the data that was signed
     * @param off offset into the data that was signed
     * @param len number of bytes signed
     * @param signature the signature
     * @return true if the signature verifies; false otherwise
     * @throws CraiException if the underlying crypto library threw an
     *     exception
     */
    public boolean verify(byte[] data, int off, int len, byte[] signature) throws CraiException;

    /**
     * Return an object containing the public contents of this key.
     *
     * @return an object which can be used to retrieve the underlying
     *     contents (usually BigIntegers)
     */
    public Contents getContents();
}
