/*
 * Created on May 22, 2005
 */

package net.lag.paramiko;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

/**
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

    /* (non-Javadoc)
     * @see net.lag.paramiko.PKey#signSSHData(java.security.SecureRandom, byte[])
     */
    public Message
    signSSHData (SecureRandom random, byte[] data)
        throws SSHException
    {
        try {
            // HOLY FREAKING MOTHER OF A GOAT SCROAT WHY DOES JAVA MAKE THIS SO PAINFUL?!?!?!
            Signature s = Signature.getInstance("SHA1withDSA");
            KeyFactory keyFac = KeyFactory.getInstance("DSA");
            PrivateKey key = keyFac.generatePrivate(new DSAPrivateKeySpec(mX, mP, mQ, mG));
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
            if (! sig.getString().equals("ssh-dss")) {
                return false;
            }
            byte[] sigData = sig.getByteString();

            Signature s = Signature.getInstance("SHA1withDSA");
            KeyFactory keyFac = KeyFactory.getInstance("DSA");
            PublicKey key = keyFac.generatePublic(new DSAPublicKeySpec(mY, mP, mQ, mG));
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
    
    
    private BigInteger mP;
    private BigInteger mQ;
    private BigInteger mG;
    private BigInteger mY;
    private BigInteger mX;
}
