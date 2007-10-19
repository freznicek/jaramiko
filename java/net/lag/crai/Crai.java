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
 * Crypto abstraction interface.
 * 
 * <p>Not every platform has JCE, so this interface allows you to wrap your
 * native crypto libraries so that they can be used by jaramiko.
 */
public interface Crai
{
    public CraiRandom getPRNG ();
    
    public CraiPrivateKey makePrivateRSAKey (BigInteger n, BigInteger d, BigInteger p, BigInteger q);
    public CraiPrivateKey makePrivateDSAKey (BigInteger x, BigInteger p, BigInteger q, BigInteger g);
    public CraiPublicKey makePublicRSAKey (BigInteger n, BigInteger e);
    public CraiPublicKey makePublicDSAKey (BigInteger y, BigInteger p, BigInteger q, BigInteger g);
    public CraiKeyPair generateRSAKeyPair (int bits);
    public CraiKeyPair generateDSAKeyPair (int bits);
    
    public CraiDigest makeSHA1 ();
    public CraiDigest makeMD5 ();
    public CraiDigest makeSHA1HMAC (byte[] key);
    public CraiDigest makeMD5HMAC (byte[] key);
    
    public CraiCipher getCipher (CraiCipherAlgorithm algorithm) throws CraiException;
    
    public BigInteger modPow (BigInteger b, BigInteger e, BigInteger m);
}
