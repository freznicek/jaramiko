/*
 * Copyright (C) 2005-2006 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
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

package net.lag.jaramiko;

import java.math.BigInteger;
import net.lag.crai.*;
import net.lag.craijce.CraiJCE;


/**
 * This only exists to allow a test to use FakeRandom.
 * 
 * @author robey
 */
public class FakeCrai
    implements Crai
{
    public
    FakeCrai ()
    {
        mCraiJCE.mCraiRandom = new FakeRandom();
    }
    
    public CraiRandom
    getPRNG ()
    {
        return new FakeRandom();
    }
    
    public CraiPrivateKey
    makePrivateRSAKey (BigInteger n, BigInteger d)
    {
        return mCraiJCE.makePrivateRSAKey(n, d);
    }
    
    public CraiPrivateKey
    makePrivateDSAKey (BigInteger x, BigInteger p, BigInteger q, BigInteger g)
    {
        return mCraiJCE.makePrivateDSAKey(x, p, q, g);
    }
    
    public CraiPublicKey
    makePublicRSAKey (BigInteger n, BigInteger e)
    {
        return mCraiJCE.makePublicRSAKey(n, e);
    }
    
    public CraiPublicKey
    makePublicDSAKey (BigInteger y, BigInteger p, BigInteger q, BigInteger g)
    {
        return mCraiJCE.makePublicDSAKey(y, p, q, g);
    }
    
    public CraiKeyPair
    generateRSAKeyPair (int bits)
    {
        return mCraiJCE.generateRSAKeyPair(bits);
    }
    
    public CraiKeyPair
    generateDSAKeyPair (int bits)
    {
        return mCraiJCE.generateDSAKeyPair(bits);
    }
    
    public CraiDigest
    makeSHA1 ()
    {
        return mCraiJCE.makeSHA1();
    }
    
    public CraiDigest
    makeMD5 ()
    {
        return mCraiJCE.makeMD5();
    }
    
    public CraiDigest
    makeSHA1HMAC (byte[] key)
    {
        return mCraiJCE.makeSHA1HMAC(key);
    }
    
    public CraiDigest
    makeMD5HMAC (byte[] key)
    {
        return mCraiJCE.makeMD5HMAC(key);
    }
    
    public CraiCipher
    getCipher (CraiCipherAlgorithm algorithm)
        throws CraiException
    {
        return mCraiJCE.getCipher(algorithm);
    }
    
    public BigInteger
    modPow (BigInteger b, BigInteger e, BigInteger m)
    {
        return mCraiJCE.modPow(b, e, m);
    }
    
    
    private CraiJCE mCraiJCE = new CraiJCE();
}
