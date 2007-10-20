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


/**
 * Container class for a key pair, containing exactly one private key and
 * exactly one public key.
 */
public class CraiKeyPair
{
    public
    CraiKeyPair (CraiPublicKey pub, CraiPrivateKey priv)
    {
        mPublic = pub;
        mPrivate = priv;
    }
    
    public CraiPublicKey
    getPublicKey ()
    {
        return mPublic;
    }
    
    public CraiPrivateKey
    getPrivateKey ()
    {
        return mPrivate;
    }
    
    
    private CraiPublicKey mPublic;
    private CraiPrivateKey mPrivate;
}
