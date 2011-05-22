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

package net.lag.jaramiko;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import net.lag.crai.Crai;
import net.lag.crai.CraiException;
import net.lag.crai.CraiKeyPair;
import net.lag.crai.CraiPrivateKey;
import net.lag.crai.CraiPublicKey;


/**
 * Standard RSA public/private key algorithm for signing and verification.
 * This wraps the java library in some SSH-specific functionality.
 */
public final class RSAKey
    extends PKey
{
    protected
    RSAKey ()
    {
        mD = null;
        mE = null;
        mN = null;
        mP = null;
        mQ = null;
    }

    public String
    getSSHName ()
    {
        return "ssh-rsa";
    }

    public boolean
    canSign ()
    {
        return (mD != null);
    }

    public int
    getBits ()
    {
        return mN.bitLength();
    }

    public byte[]
    toByteArray()
    {
        Message m = new Message();
        m.putString(getSSHName());
        m.putMPZ(mE);
        m.putMPZ(mN);
        return m.toByteArray();
    }

    public Message
    signSSHData (Crai crai, byte[] data)
        throws SSHException
    {
        try {
            CraiPrivateKey rsa = crai.makePrivateRSAKey(mN, mD, mP, mQ);
            Message m = new Message();
            m.putString(getSSHName());
            m.putByteString(rsa.sign(data, 0, data.length));
            return m;
        } catch (CraiException x) {
            x.printStackTrace();
            throw new SSHException("Java publickey error: " + x);
        }
    }

    public boolean
    verifySSHSignature (Crai crai, byte[] data, Message sig)
        throws SSHException
    {
        try {
            if (! sig.getString().equals("ssh-rsa")) {
                return false;
            }
            byte[] sigData = sig.getByteString();

            CraiPublicKey rsa = crai.makePublicRSAKey(mN, mE);
            return rsa.verify(data, 0, data.length, sigData);
        } catch (CraiException x) {
            throw new SSHException("Java publickey error: " + x);
        }
    }

    protected void
    buildFromBER (BigInteger[] ints)
        throws SSHException
    {
        if (ints.length < 6) {
            throw new SSHException("Not a valid RSA private key file (bad ber encoding)");
        }
        mN = ints[1];
        mE = ints[2];
        mD = ints[3];
        mP = ints[4];
        mQ = ints[5];
    }

    protected void
    buildFromMessage (Message m)
        throws SSHException
    {
        mE = m.getMPZ();
        mN = m.getMPZ();
    }

    public void
    writePrivateKeyToStream (OutputStream os, String password)
        throws IOException
    {
        BigInteger[] nums = new BigInteger[9];
        nums[0] = BigInteger.ZERO;
        nums[1] = mN;
        nums[2] = mE;
        nums[3] = mD;
        nums[4] = mP;
        nums[5] = mQ;
        BigInteger one = new BigInteger("1");
        nums[6] = mD.mod(mP.subtract(one));
        nums[7] = mD.mod(mQ.subtract(one));
        nums[8] = mQ.modInverse(mP);
        writePrivateKeyToStream("RSA", os, nums, password);
    }

    /**
     * Generate a new RSA private/public key pair.  This operation may take
     * a non-trivial amount of time.  The actual key generation is
     * delegated to {@link Crai}.
     *
     * @param bits bit size of the key to generate
     * @return a new RSA key
     * @throws SSHException if there's an error within the underlying crypto
     *     library
     */
    public static RSAKey
    generate (Crai crai, int bits)
        throws SSHException
    {
        try {
            CraiKeyPair pair = crai.generateRSAKeyPair(bits);
            CraiPrivateKey.RSAContents priv = (CraiPrivateKey.RSAContents) pair.getPrivateKey().getContents();
            CraiPublicKey.RSAContents pub = (CraiPublicKey.RSAContents) pair.getPublicKey().getContents();

            RSAKey key = new RSAKey();
            key.mE = pub.getE();
            key.mN = pub.getN();
            key.mD = priv.getD();
            key.mP = priv.getP();
            key.mQ = priv.getQ();
            return key;
        } catch (Exception x) {
            throw new SSHException("Java publickey error: " + x);
        }
    }

    /**
     * Create an RSA private key object from the component integers. This
     * method assumes the integers have come from some other reliable source.
     * The parameter names identify the required numbers from the RSA
     * algorithm.
     *
     * <p> Please don't use this method to generate a new key from scratch.
     * Picking correct values for these parameters is tricky.
     * Use {@link #generate(Crai, int)} to generate a new key.
     *
     * @param e the RSA "e"
     * @param d the RSA "d"
     * @param n the RSA "n"
     * @param p the RSA "p"
     * @param q the RSA "q"
     * @return an RSA private key object
     */
    public static RSAKey
    build (BigInteger e, BigInteger d, BigInteger n, BigInteger p, BigInteger q)
    {
        RSAKey key = new RSAKey();
        key.mE = e;
        key.mD = d;
        key.mN = n;
        key.mP = p;
        key.mQ = q;
        return key;
    }

    /**
     * Create an RSA public key object from the component integers. Such a key
     * can be used only to verify signatures, not sign data.
     *
     * @param e the RSA "e"
     * @param n the RSA "n"
     * @return an RSA public key object
     */
    public static RSAKey
    build (BigInteger e, BigInteger n)
    {
        RSAKey key = new RSAKey();
        key.mE = e;
        key.mN = n;
        return key;
    }

    public CraiPrivateKey
    toPrivateKey (Crai crai)
    {
        return crai.makePrivateRSAKey(mN, mD, mP, mQ);
    }

    public CraiPublicKey
    toPublicKey (Crai crai)
    {
        return crai.makePublicRSAKey(mN, mE);
    }


    private BigInteger mE;
    private BigInteger mD;
    private BigInteger mN;
    private BigInteger mP;
    private BigInteger mQ;
}
