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
 * Standard DSS public/private key algorithm for signing and verification.
 * This wraps the java library in some SSH-specific functionality.
 */
public class DSSKey
    extends PKey
{
    public String
    getSSHName ()
    {
        return "ssh-dss";
    }

    public boolean
    canSign ()
    {
        return mX != null;
    }

    public int
    getBits ()
    {
        return mP.bitLength();
    }

    public byte[]
    toByteArray ()
    {
        Message m = new Message();
        m.putString(getSSHName());
        m.putMPZ(mP);
        m.putMPZ(mQ);
        m.putMPZ(mG);
        m.putMPZ(mY);
        return m.toByteArray();
    }

    public Message
    signSSHData (Crai crai, byte[] data)
        throws SSHException
    {
        try {
            CraiPrivateKey dsa = crai.makePrivateDSAKey(mX, mP, mQ, mG);
            byte[] sig = dsa.sign(data, 0, data.length);

            Message m = new Message();
            m.putString(getSSHName());
            m.putByteString(sig);
            return m;
        } catch (CraiException x) {
            throw new SSHException("Java publickey error: " + x);
        }
    }

    public boolean
    verifySSHSignature (Crai crai, byte[] data, Message sig)
        throws SSHException
    {
        try {
            if (! sig.getString().equals("ssh-dss")) {
                return false;
            }
            byte[] sigData = sig.getByteString();

            if (sigData.length != 40) {
                throw new SSHException("DSS signature must be exactly 40 bytes! (is: " + sigData.length + ")");
            }
            CraiPublicKey dsa = crai.makePublicDSAKey(mY, mP, mQ, mG);
            return dsa.verify(data, 0, data.length, sigData);
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
        mP = ints[1];
        mQ = ints[2];
        mG = ints[3];
        mY = ints[4];
        mX = ints[5];
    }

    protected void
    buildFromMessage (Message m)
    {
        mP = m.getMPZ();
        mQ = m.getMPZ();
        mG = m.getMPZ();
        mY = m.getMPZ();
    }

    public void
    writePrivateKeyToStream (OutputStream os, String password)
        throws IOException
    {
        BigInteger[] nums = new BigInteger[6];
        nums[0] = BigInteger.ZERO;
        nums[1] = mP;
        nums[2] = mQ;
        nums[3] = mG;
        nums[4] = mY;
        nums[5] = mX;
        writePrivateKeyToStream("DSA", os, nums, password);
    }

    /**
     * Generate a new DSS private/public key pair.  This operation may take
     * a non-trivial amount of time.  The actual key generation is
     * delegated to {@link Crai}.
     *
     * @param bits bit size of the key to generate
     * @return a new DSS key
     * @throws SSHException if there's an error within the underlying crypto
     *     library
     */
    public static DSSKey
    generate (Crai crai, int bits)
        throws SSHException
    {
        try {
            CraiKeyPair pair = crai.generateDSAKeyPair(bits);
            CraiPrivateKey.DSAContents priv = (CraiPrivateKey.DSAContents) pair.getPrivateKey().getContents();
            CraiPublicKey.DSAContents pub = (CraiPublicKey.DSAContents) pair.getPublicKey().getContents();

            DSSKey key = new DSSKey();
            key.mP = pub.getP();
            key.mQ = pub.getQ();
            key.mG = pub.getG();
            key.mX = priv.getX();
            key.mY = pub.getY();
            return key;
        } catch (Exception x) {
            throw new SSHException("Java publickey error: " + x);
        }
    }

    /**
     * Create a DSS private key object from the component integers. This
     * method assumes the integers have come from some other reliable source.
     * The parameter names identify the required numbers from the DSS
     * algorithm.
     *
     * <p> Please don't use this method to generate a new key from scratch.
     * Picking correct values for these parameters is tricky.
     * Use {@link #generate(Crai, int)} to generate a new key.
     *
     * @param p the DSS "p"
     * @param q the DSS "q"
     * @param g the DSS "g"
     * @param y the DSS "y"
     * @param x the DSS "x"
     * @return a DSS private key object
     */
    public static DSSKey
    build (BigInteger p, BigInteger q, BigInteger g, BigInteger y, BigInteger x)
    {
        DSSKey key = new DSSKey();
        key.mP = p;
        key.mQ = q;
        key.mG = g;
        key.mY = y;
        key.mX = x;
        return key;
    }

    /**
     * Create a DSS public key object from the component integers. Such a key
     * can be used only to verify signatures, not sign data.
     *
     * @param p the DSS "p"
     * @param q the DSS "q"
     * @param g the DSS "g"
     * @param y the DSS "y"
     * @return a DSS public key object
     */
    public static DSSKey
    build (BigInteger p, BigInteger q, BigInteger g, BigInteger y)
    {
        DSSKey key = new DSSKey();
        key.mP = p;
        key.mQ = q;
        key.mG = g;
        key.mY = y;
        return key;
    }

    public CraiPrivateKey
    toPrivateKey (Crai crai)
    {
        return crai.makePrivateDSAKey(mX, mP, mQ, mG);
    }

    public CraiPublicKey
    toPublicKey (Crai crai)
    {
        return crai.makePublicDSAKey(mY, mP, mQ, mG);
    }


    private BigInteger mP;
    private BigInteger mQ;
    private BigInteger mG;
    private BigInteger mY;
    private BigInteger mX;
}
