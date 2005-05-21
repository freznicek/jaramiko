/*
 * Created on May 15, 2005
 */

package net.lag.paramiko;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;

/**
 * Standard RSA public-key signing and verification.  This wraps the java
 * library in some SSH-specific functionality.
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
    
    protected void
    buildFromBER (BigInteger[] ints)
        throws SSHException
    {
        if (ints.length < 5) {
            throw new SSHException("Not a valid RSA private key file (bad ber encoding)");
        }
        mN = ints[0];
        mE = ints[1];
        mD = ints[2];
        mP = ints[3];
        mQ = ints[4];
//        self.size = util.bit_length(self.n)
    }
    

    private BigInteger mE;
    private BigInteger mD;
    private BigInteger mN;
    private BigInteger mP;
    private BigInteger mQ;
}
