/*
 * Copyright (C) 2007 Robey Pointer <robey@lag.net>
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

package net.lag.jaramiko;


/**
 * A description of the negotiated parameters of this SSH transport. The
 * description includes the name of the key exchange algorithm, the type of
 * server key used, the encryption in each direction, compression, etc.
 */
public class TransportDescription
{
    /* package */
    TransportDescription ()
    {
        // pass
    }
    
    /**
     * Return the name of the key exchange algorithm in use. One example is
     * <code>"diffie-hellman-group1-sha1"</code>
     * 
     * @return the key exchange algorithm in use
     */
    public String
    getKeyExchangeAlgorithm ()
    {
        return mKexName;
    }
    
    /**
     * Return the type of key used by the server. This is usually either
     * <code>"ssh-rsa"</code> or <code>"ssh-dss"</code>.
     * 
     * @return the type of key used by the server
     */
    public String
    getServerKeyType ()
    {
        return mServerKeyType;
    }
    
    /**
     * Return the name of the negotiated cipher used for outbound traffic.
     * 
     * @return the cipher name
     */
    public String
    getLocalCipherName ()
    {
        return mLocalCipherName;
    }
    
    /**
     * Return the key size (in bits) of the negotiated cipher used for
     * outbound traffic.
     * 
     * @return the key size in bits
     */
    public int
    getLocalCipherBits ()
    {
        return mLocalCipher.mKeySize * 8;
    }
    
    /**
     * Return the name of the negotiated cipher used for inbound traffic.
     * 
     * @return the cipher name
     */
    public String
    getRemoteCipherName ()
    {
        return mRemoteCipherName;
    }
    
    /**
     * Return the key size (in bits) of the negotiated cipher used for
     * inbound traffic.
     * 
     * @return the key size in bits
     */
    public int
    getRemoteCipherBits ()
    {
        return mRemoteCipher.mKeySize * 8;
    }
    
    /**
     * Return the name of the MAC algorithm used for outbound traffic. An
     * example is <code>"hmac-sha1"</code>.
     * 
     * @return the MAC algorithm name
     */
    public String
    getLocalMacAlgorithm ()
    {
        return mLocalMacAlgorithm;
    }
    
    /**
     * Return the number of bits used on outbound MACs.
     * 
     * @return the bit size of the MAC
     */
    public int
    getLocalMacBits ()
    {
        return mLocalMac.mDigestSize * 8;
    }
    
    /**
     * Return the name of the MAC algorithm used for inbound traffic. An
     * example is <code>"hmac-sha1"</code>.
     * 
     * @return the MAC algorithm name
     */
    public String
    getRemoteMacAlgorithm ()
    {
        return mRemoteMacAlgorithm;
    }
    
    /**
     * Return the number of bits used on inbound MACs.
     * 
     * @return the bits size of the MAC
     */
    public int
    getRemoteMacBits ()
    {
        return mRemoteMac.mDigestSize * 8;
    }
    
    /**
     * Return the name of the compression used for outbound traffic, or
     * <code>"none"</code> for no compression.
     * 
     * @return the name of the compression algorithm
     */
    public String
    getLocalCompression ()
    {
        return mLocalCompression;
    }
    
    /**
     * Return the name of the compression used for inbound traffic, or
     * <code>"none"</code> for no compression.
     * 
     * @return the name of the compression algorithm
     */
    public String
    getRemoteCompression ()
    {
        return mRemoteCompression;
    }
    
    public String
    toString ()
    {
        return "kex=" + mKexName + "; server_key=" + mServerKeyType + "; outbound_cipher=" +
            mLocalCipherName + " (bits=" + mLocalCipher.mBlockSize * 8 + "); inbound cipher=" +
            mRemoteCipherName + " (bits=" + mRemoteCipher.mBlockSize * 8 + "); outbound_mac=" +
            mLocalMacAlgorithm + " (bits=" + mLocalMac.mDigestSize * 8 + "); inbound_mac=" +
            mRemoteMacAlgorithm + " (bits=" + mRemoteMac.mDigestSize * 8 + "); outbound_compress=" +
            mLocalCompression + "; inbound_compress=" + mRemoteCompression;
    }
    
    
    /* package */ String mKexName;
    /* package */ String mServerKeyType;
    /* package */ String mLocalCipherName;
    /* package */ CipherDescription mLocalCipher;
    /* package */ String mRemoteCipherName;
    /* package */ CipherDescription mRemoteCipher;
    /* package */ String mLocalMacAlgorithm;
    /* package */ MacDescription mLocalMac;
    /* package */ String mRemoteMacAlgorithm;
    /* package */ MacDescription mRemoteMac;
    /* package */ String mLocalCompression;
    /* package */ String mRemoteCompression;
}
