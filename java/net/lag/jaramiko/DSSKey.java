/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
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
 * 
 * 
 * Created on May 22, 2005
 */

package net.lag.jaramiko;

import java.math.BigInteger;

import net.lag.crai.Crai;
import net.lag.crai.CraiException;
import net.lag.crai.CraiKeyPair;
import net.lag.crai.CraiPrivateKey;
import net.lag.crai.CraiPublicKey;


/**
 * Standard DSS public/private key algorithm for signing and verification.
 * This wraps the java library in some SSH-specific functionality.
 * 
 * @author robey
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

    
    
    private BigInteger mP;
    private BigInteger mQ;
    private BigInteger mG;
    private BigInteger mY;
    private BigInteger mX;
}
