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
 */

package net.lag.craijce;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
    
    
    private static class JCEDigest
        implements CraiDigest
    {
        public
        JCEDigest (MessageDigest d)
        {
            mDigest = d;
        }
        
        public void
        reset ()
        {
            mDigest.reset();
        }
        
        public void
        update (byte[] data, int off, int len)
        {
            mDigest.update(data, off, len);
        }
        
        public byte[]
        finish ()
        {
            return mDigest.digest();
        }
        
        public void
        finish (byte[] out, int off)
            throws CraiException
        {
            try {
                mDigest.digest(out, off, mDigest.getDigestLength());
            } catch (GeneralSecurityException x) {
                throw new CraiException(x.toString());
            }
        }
        
        
        private MessageDigest mDigest;
    }
    
    private static class JCEHMAC
        implements CraiDigest
    {
        public
        JCEHMAC (Mac mac)
        {
            mMac = mac;
        }
        
        public void
        reset ()
        {
            mMac.reset();
        }
        
        public void
        update (byte[] data, int off, int len)
        {
            mMac.update(data, off, len);
        }
        
        public byte[]
        finish ()
        {
            return mMac.doFinal();
        }
        
        public void
        finish (byte[] out, int off)
            throws CraiException
        {
            try {
                mMac.doFinal(out, off);
            } catch (GeneralSecurityException x) {
                throw new CraiException(x.toString());
            }
        }
        
        
        private Mac mMac;
    }
    
    
    private static class JCECipher
        implements CraiCipher
    {
        public
        JCECipher (String javaName)
            throws CraiException
        {
            mJavaName = javaName;
            try {
                mCipher = Cipher.getInstance(javaName);
            } catch (GeneralSecurityException x) {
                throw new CraiException("cipher " + javaName + " not found: " + x);
            }
        }
        
        public void
        initEncrypt (byte[] key, byte[] iv)
            throws CraiException
        {
            // isn't this insane?
            String algName = mJavaName.split("/")[0];
            try {
                AlgorithmParameters param = AlgorithmParameters.getInstance(algName);
                param.init(new IvParameterSpec(iv));
                mCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algName), param);
            } catch (GeneralSecurityException x) {
                throw new CraiException("cipher " + mJavaName + " encrypt init error: " + x);
            } catch (SecurityException x) {
                throw new CraiException("cipher " + mJavaName + " encrypt init error: " + x);
            }
        }
        
        public void
        initDecrypt (byte[] key, byte[] iv)
            throws CraiException
        {
            String algName = mJavaName.split("/")[0];
            try {
                AlgorithmParameters param = AlgorithmParameters.getInstance(algName);
                param.init(new IvParameterSpec(iv));
                mCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algName), param);
            } catch (GeneralSecurityException x) {
                throw new CraiException("cipher " + mJavaName + " decrypt init error: " + x);
            } catch (SecurityException x) {
                throw new CraiException("cipher " + mJavaName + " decrypt init error: " + x);
            }
        }
        
        public void
        process (byte[] in, int off, int len, byte[] out, int off_out)
            throws CraiException
        {
            try{
                mCipher.update(in, off, len, out, off_out);
            } catch (GeneralSecurityException x) {
                throw new CraiException("cipher " + mJavaName + " process error: " + x);
            }
        }
        
        
        private String mJavaName;
        private Cipher mCipher;
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
    
    public CraiDigest
    makeSHA1 ()
    {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            return new JCEDigest(sha);
        } catch (NoSuchAlgorithmException x) {
            throw new RuntimeException("Unable to find SHA-1 algorithm");
        }
    }
    
    public CraiDigest
    makeMD5 ()
    {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            return new JCEDigest(md5);
        } catch (NoSuchAlgorithmException x) {
            throw new RuntimeException("Unable to find MD5 algorithm");
        }
    }
    
    public CraiDigest
    makeSHA1HMAC (byte[] key)
    {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return new JCEHMAC(mac);
        } catch (GeneralSecurityException x) {
            throw new RuntimeException("Unable to find SHA-1 HMAC algorithm");
        }
    }
    
    public CraiDigest
    makeMD5HMAC (byte[] key)
    {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            return new JCEHMAC(mac);
        } catch (GeneralSecurityException x) {
            throw new RuntimeException("Unable to find MD5 HMAC algorithm");
        }
    }
    
    public CraiCipher
    getCipher (CraiCipherAlgorithm algorithm)
        throws CraiException
    {
        if (algorithm == CraiCipherAlgorithm.DES3_CBC) {
            return new JCECipher("DESede/CBC/NoPadding");
        } else if (algorithm == CraiCipherAlgorithm.AES_CBC) {
            return new JCECipher("AES/CBC/NoPadding");
        } else if (algorithm == CraiCipherAlgorithm.BLOWFISH_CBC) {
            return new JCECipher("Blowfish/CBC/NoPadding");
        } else {
            throw new CraiException("cipher algorithm not implemented");
        }
    }

    
    public CraiRandom mCraiRandom = new JCERandom();
}
