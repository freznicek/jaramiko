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
 * Created on May 15, 2005
 */

package net.lag.jaramiko;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


/**
 * Standard RSA public/private key algorithm for signing and verification.
 * This wraps the java library in some SSH-specific functionality.
 * 
 * @author robey
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
        //mP = null;
        //mQ = null;
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
    signSSHData (SecureRandom random, byte[] data)
        throws SSHException
    {
        try {
            // HOLY FREAKING MOTHER OF A GOAT SCROAT WHY DOES JAVA MAKE THIS SO PAINFUL?!?!?!
            Signature s = Signature.getInstance("SHA1withRSA");
            KeyFactory keyFac = KeyFactory.getInstance("RSA");
            PrivateKey key = keyFac.generatePrivate(new RSAPrivateKeySpec(mN, mD));
            s.initSign(key, random);
            s.update(data);
            
            Message m = new Message();
            m.putString(getSSHName());
            m.putByteString(s.sign());
            return m;
        } catch (Exception x) {
            throw new SSHException("Java publickey error: " + x);
        }
    }
    
    public boolean
    verifySSHSignature (byte[] data, Message sig)
        throws SSHException
    {
        try {
            if (! sig.getString().equals("ssh-rsa")) {
                return false;
            }
            byte[] sigData = sig.getByteString();

            Signature s = Signature.getInstance("SHA1withRSA");
            KeyFactory keyFac = KeyFactory.getInstance("RSA");
            PublicKey key = keyFac.generatePublic(new RSAPublicKeySpec(mN, mE));
            s.initVerify(key);
            s.update(data);
            return s.verify(sigData);
        } catch (Exception x) {
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
        //mP = ints[4];
        //mQ = ints[5];
    }
    
    protected void
    buildFromMessage (Message m)
        throws SSHException
    {
        mE = m.getMPZ();
        mN = m.getMPZ();
    }
    
    /**
     * Theoretically generate a new RSA private/public key pair.  However,
     * DON'T CALL THIS METHOD!  Java's key generation is broken and never
     * finishes on my Mac, so I'm leaving this stuff stubbed out.
     * 
     * @param bits bit size of the key to generate
     * @param random a source of random bytes
     * @return a new RSA key
     * @throws SSHException if there's an error within java's crypto library
     */
    public static RSAKey
    generate (int bits, SecureRandom random)
        throws SSHException
    {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits, random);
            KeyPair kp = generator.generateKeyPair();
            
            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
            RSAKey key = new RSAKey();
            key.mE = pub.getPublicExponent();
            key.mN = pub.getModulus();
            key.mD = priv.getPrivateExponent();
            // unfortunately, sun doesn't provide P and Q here.
            return key;
        } catch (Exception x) {
            throw new SSHException("Java publickey error: " + x);
        }
    }
    

    private BigInteger mE;
    private BigInteger mD;
    private BigInteger mN;
    //private BigInteger mP;
    //private BigInteger mQ;
}
