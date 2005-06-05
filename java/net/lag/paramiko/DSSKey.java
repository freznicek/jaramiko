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
 * Implementation of DSS public/private key algorithm for SSH2.
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
            byte[] sig = s.sign();
            
            /* decode java's odd signature format:
             * java returns a ber sequence containing (r, s) but ssh2 expects
             * a 40-byte buffer containing the 20 bytes of r followed by the
             * 20 bytes of s, with no sign extension.
             */
            BigInteger[] rs = decodeBERSequence(sig);
            byte[] rb = rs[0].toByteArray();
            byte[] sb = rs[1].toByteArray();
            sig = new byte[40];
            System.arraycopy(rb, rb.length - 20, sig, 0, 20);
            System.arraycopy(sb, sb.length - 20, sig, 20, 20);
            
            Message m = new Message();
            m.putString(getSSHName());
            m.putByteString(sig);
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

            if (sigData.length != 40) {
                throw new SSHException("DSS signature must be exactly 40 bytes! (is: " + sigData.length + ")");
            }
            /* build up a fake ber sequence containing r and s.  this is
             * terrible to behold but i didn't feel like implementing the
             * ber encoding algorithm just to workaround one tiny bit of
             * oddness with java's API.
             */
            byte[] argh = new byte[48];
            argh[0] = 0x30;
            argh[1] = 46;
            argh[2] = 2;
            argh[3] = 21;
            argh[4] = 0;
            System.arraycopy(sigData, 0, argh, 5, 20);
            argh[25] = 2;
            argh[26] = 21;
            argh[27] = 0;
            System.arraycopy(sigData, 20, argh, 28, 20);
            
            Signature s = Signature.getInstance("SHA1withDSA");
            KeyFactory keyFac = KeyFactory.getInstance("DSA");
            PublicKey key = keyFac.generatePublic(new DSAPublicKeySpec(mY, mP, mQ, mG));
            s.initVerify(key);
            s.update(data);
            return s.verify(argh);
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
