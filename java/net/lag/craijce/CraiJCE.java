package net.lag.craijce;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import net.lag.crai.*;


/**
 * Default Crai implementation that just wraps java's JCE classes.
 * 
 * @author robey
 */
public class CraiJCE
    implements Crai
{
    private static class JCERandom
        implements CraiRandom
    {
        public
        JCERandom ()
        {
            mRandom = new SecureRandom();
        }
        
        public void
        getBytes (byte[] b)
        {
            mRandom.nextBytes(b);
        }
        
        
        public SecureRandom mRandom;
    }
    
    private class JCEPrivateRSAKey
        implements CraiPrivateKey
    {
        public
        JCEPrivateRSAKey (BigInteger n, BigInteger d)
        {
            mN = n;
            mD = d;
        }
        
        public byte[]
        sign(byte[] b, int off, int len)
            throws CraiException
        {
            try {
                // HOLY FREAKING MOTHER OF A GOAT SCROAT WHY DOES JAVA MAKE THIS SO PAINFUL?!?!?!
                Signature s = Signature.getInstance("SHA1withRSA");
                KeyFactory keyFac = KeyFactory.getInstance("RSA");
                PrivateKey key = keyFac.generatePrivate(new RSAPrivateKeySpec(mN, mD));
                s.initSign(key, ((JCERandom) mCraiRandom).mRandom);
                s.update(b, off, len);
                return s.sign();
            } catch (Exception e) {
                // JCE can throw weird exceptions at every stage :/
                throw new CraiException("error performing RSA signature: " + e);
            }
        }
        
        
        private BigInteger mN;
        private BigInteger mD;
    }
    
    private class JCEPrivateDSAKey
        implements CraiPrivateKey
    {
        public
        JCEPrivateDSAKey (BigInteger x, BigInteger p, BigInteger q, BigInteger g)
        {
            mX = x;
            mP = p;
            mQ = q;
            mG = g;
        }
        
        public byte[]
        sign(byte[] b, int off, int len)
            throws CraiException
        {
            try {
                // HOLY FREAKING MOTHER OF A GOAT SCROAT WHY DOES JAVA MAKE THIS SO PAINFUL?!?!?!
                Signature s = Signature.getInstance("SHA1withDSA");
                KeyFactory keyFac = KeyFactory.getInstance("DSA");
                PrivateKey key = keyFac.generatePrivate(new DSAPrivateKeySpec(mX, mP, mQ, mG));
                s.initSign(key, ((JCERandom) mCraiRandom).mRandom);
                s.update(b, off, len);
                return s.sign();
            } catch (Exception e) {
                // JCE can throw weird exceptions at every stage :/
                throw new CraiException("error performing DSA signature: " + e);
            }
        }


        private BigInteger mX;
        private BigInteger mP;
        private BigInteger mQ;
        private BigInteger mG;
    }
    
    private class JCEPublicRSAKey
        implements CraiPublicKey
    {
        public
        JCEPublicRSAKey (BigInteger n, BigInteger e)
        {
            mN = n;
            mE = e;
        }
        
        public boolean
        verify (byte[] data, int off, int len, byte[] signature)
            throws CraiException
        {
            try {
                Signature s = Signature.getInstance("SHA1withRSA");
                KeyFactory keyFac = KeyFactory.getInstance("RSA");
                PublicKey key = keyFac.generatePublic(new RSAPublicKeySpec(mN, mE));
                s.initVerify(key);
                s.update(data);
                return s.verify(signature);
            } catch (Exception e) {
                throw new CraiException("error verifying RSA signature: " + e);
            }
        }
        
        
        private BigInteger mN;
        private BigInteger mE;
    }
    
    private class JCEPublicDSAKey
        implements CraiPublicKey
    {
        public
        JCEPublicDSAKey (BigInteger y, BigInteger p, BigInteger q, BigInteger g)
        {
            mY = y;
            mP = p;
            mQ = q;
            mG = g;
        }
        
        public boolean
        verify (byte[] data, int off, int len, byte[] signature)
            throws CraiException
        {
            try {
                Signature s = Signature.getInstance("SHA1withDSA");
                KeyFactory keyFac = KeyFactory.getInstance("DSA");
                PublicKey key = keyFac.generatePublic(new DSAPublicKeySpec(mY, mP, mQ, mG));
                s.initVerify(key);
                s.update(data, off, len);
                return s.verify(signature);
            } catch (Exception e) {
                throw new CraiException("error verifying DSA signature: " + e);
            }
        }
        
        
        private BigInteger mY;
        private BigInteger mP;
        private BigInteger mQ;
        private BigInteger mG;
    }

    
    public CraiRandom
    getPRNG ()
    {
        return mCraiRandom;
    }
    
    public CraiPrivateKey
    makePrivateRSAKey (BigInteger n, BigInteger d)
    {
        return new JCEPrivateRSAKey(n, d);
    }
    
    public CraiPrivateKey
    makePrivateDSAKey (BigInteger x, BigInteger p, BigInteger q, BigInteger g)
    {
        return new JCEPrivateDSAKey(x, p, q, g);
    }
    
    public CraiPublicKey
    makePublicRSAKey (BigInteger n, BigInteger e)
    {
        return new JCEPublicRSAKey(n, e);
    }
    
    public CraiPublicKey
    makePublicDSAKey (BigInteger y, BigInteger p, BigInteger q, BigInteger g)
    {
        return new JCEPublicDSAKey(y, p, q, g);
    }
    
    
    public CraiRandom mCraiRandom = new JCERandom();
}
