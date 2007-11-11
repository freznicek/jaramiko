/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
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

import java.io.*;
import java.math.BigInteger;
import java.util.*;

import net.lag.crai.*;


/**
 * Common base class for public-key schemes.
 */
public abstract class PKey
{
    protected
    PKey ()
    {
        // pass
    }
    
    /**
     * Return the SSH-specific algorithm name for this public key algorithm.
     * Examples are <code>"ssh-rsa"</code> and <code>"ssh-dss"</code>.
     * 
     * @return the name of this algorithm
     */
    public abstract String getSSHName ();
    
    /**
     * Return true if this key contains the "private key" information needed
     * to perform signatures.
     * 
     * @return true if this key can sign data
     */
    public abstract boolean canSign ();
    
    /**
     * Return the number of significant bits in this key.  This can be used
     * as a rough indication of the strength of the underlying key.
     * 
     * @return the number of significant bits in this key
     */
    public abstract int getBits ();
    
    /**
     * Return a byte array representation of the public part(s) of this key,
     * in SSH2 normalized form (typically some kind of {@link Message}).
     * 
     * @return a byte array of the public part(s) of this key
     */
    public abstract byte[] toByteArray ();
    
    /**
     * Sign a blob of data using this private key, and return a {@link Message}
     * representing the signature.
     * 
     * @param crai the crypto abstraction layer
     * @param data the data to sign
     * @return a {@link Message} representing the signature
     * @throws SSHException if there is an error with underlying java crypto
     *     libraries
     */
    public abstract Message signSSHData (Crai crai, byte[] data) throws SSHException;
    
    /**
     * Verify an SSH2 signature against a blob of data using this public key.
     * If the data appears to have been signed by this key, this method
     * returns true.
     * 
     * @param crai the crypto abstraction layer
     * @param data the data that was signed
     * @param sig the message containing the signature
     * @return true if the signature is valid
     * @throws SSHException if there is an error with underlying java crypto
     *     libraries
     */
    public abstract boolean verifySSHSignature (Crai crai, byte[] data, Message sig) throws SSHException;

    /**
     * Convert the public elements of this key into a {@link CraiPublicKey}
     * object, which will contain the component integers.
     * 
     * @param crai the crypto abstraction layer
     * @return a public key object
     */
    public abstract CraiPublicKey toPublicKey (Crai crai);
    
    /**
     * Convert the private elements of this key into a {@link CraiPrivateKey}
     * object, which will contain the component integers.
     * 
     * @param crai the crypto abstraction layer
     * @return a private key object
     */
    public abstract CraiPrivateKey toPrivateKey (Crai crai);
    
    /**
     * Return an MD5 fingerprint of the public part of this key.  Nothing
     * secret is revealed.  Effectively this is just the MD5 of the result
     * of {@link #toByteArray}.
     * 
     * @return a 16-byte MD5 fingerprint 
     */
    public byte[]
    getFingerprint ()
    {
        CraiDigest md5 = BaseTransport.getCrai().makeMD5();
        byte[] d = toByteArray();
        md5.update(d, 0, d.length);
        return md5.finish();
    }

    /**
     * Return a base64 string containing the public part of this key.  Nothing
     * secret is revealed.  This format is compatible with that used to store
     * public key files or recognized host keys.
     * 
     * @return a base64 string containing the public part of the key
     */
    public String
    getBase64 ()
    {
        return Base64.encodeBytes(toByteArray(), Base64.DONT_BREAK_LINES);
    }
    
    /**
     * A PKey compares equal to another PKey if the public parts of the key
     * are equal.
     */
    public boolean
    equals (Object o)
    {
        if (this == o) {
            return true;
        }
        if (! (o instanceof PKey)) {
            return false;
        }
        PKey other = (PKey) o;
        return Arrays.equals(toByteArray(), other.toByteArray());
    }
    
    public String
    toString ()
    {
        return "<" + getClass().getName() + " " + Util.encodeHex(getFingerprint()) + ">";
    }
    
    /**
     * Initialize a key from an array of BigIntegers (decoded from a BER
     * stream).  This data has usually been read from a private key file,
     * and this method is the final step in creating a key from such a file.
     * 
     * @param data the list of BigIntegers from a BER stream
     */
    protected abstract void buildFromBER (BigInteger[] data) throws SSHException;
    
    /**
     * Initialize a key from an SSH Message.
     * 
     * @param m the key Message
     * @throws SSHException if the Message is corrupted
     */
    protected abstract void buildFromMessage (Message m) throws SSHException;
    
    
    /**
     * Return a public key from base64 data.  The base64 encoding of a key
     * is SSH-specific and only contains the public key.  It can be fetched
     * from an existing key via {@link #getBase64}.
     * 
     * @param s the string containing the base64 data
     * @return a public key ({@link RSAKey} or {@link DSSKey})
     * @throws SSHException if the base64 data is corrupted
     */
    public static PKey
    createFromBase64 (String s)
        throws SSHException
    {
        return createFromData(Base64.decode(s));
    }
    
    /**
     * Return a public key from an SSH byte stream (an undecoded
     * {@link Message}).  Only the public key is encoded or extracted, so only
     * the public key is returned.
     * 
     * @param data the key data
     * @return a public key ({@link RSAKey} or {@link DSSKey})
     * @throws SSHException if the data is corrupted
     */
    public static PKey
    createFromData (byte[] data)
        throws SSHException
    {
        return createFromMessage(new Message(data));
    }
    
    /**
     * Return a public key from an SSH {@link Message}.  Only the public key
     * is encoded or extracted, so only the public key is returned.
     *  
     * @param m the Message
     * @return a public key ({@link RSAKey} or {@link DSSKey})
     * @throws SSHException if the Message is corrupted
     */
    public static PKey
    createFromMessage (Message m)
        throws SSHException
    {
        String name = m.getString();
        Class keyClass = (Class) sNameMap.get(name);
        if (keyClass == null) {
            throw new SSHException("Unknown key type " + name);
        }
        PKey key = null;
        try {
            key = (PKey) keyClass.newInstance();
        } catch (Exception x) {
            throw new SSHException("Internal java error: " + x);
        }
        key.buildFromMessage(m);
        return key;
    }
    
    /**
     * Read a private key from a standard SSH2 key file (ASCII).  If the key
     * is read correctly, a new {@link RSAKey} or {@link DSSKey} will be
     * returned.  Otherwise, an exception will be thrown.
     * 
     * <p>If the key file is encrypted and no password is given,
     * {@link PasswordRequiredException} will be thrown.  If a password is
     * given but it's incorrect, the key file will appear to be scrambled
     * and an {@link SSHException} or IOException will be thrown.
     * 
     * @param is the stream to read the key file from
     * @param password (null-ok) a password to use if the file is encrypted
     * @return a new PKey instance ({@link RSAKey} or {@link DSSKey})
     * @throws IOException if there was an error reading or decrypting the
     *     key file
     */
    public static PKey
    readPrivateKeyFromStream (InputStream is, String password)
        throws IOException
    {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        Class keyClass = null;
        
        while (true) {
            String line = reader.readLine();
            if (line == null) {
                throw new IOException("No private key in stream");
            }
            if (line.startsWith("-----BEGIN ") && line.endsWith(" PRIVATE KEY-----")) {
                String name = line.substring(11, line.length() - 17);
                keyClass = (Class) sBannerMap.get(name);
                if (keyClass == null) {
                    throw new SSHException("Unknown key type " + name);
                }
                break;
            }
        }
        
        boolean inHeaders = true;
        Map headers = new HashMap();
        ByteArrayOutputStream keyData = new ByteArrayOutputStream();
        
        while (true) {
            String line = reader.readLine();
            if (line == null) {
                throw new IOException("Truncated private key");
            }

            if (inHeaders) {
                String[] fields = Util.splitString(line, ": ", 2);
                if (fields.length < 2) {
                    inHeaders = false;
                } else {
                    headers.put(fields[0].toLowerCase(), fields[1]);
                    continue;
                }
            }

            if (line.startsWith("-----END ") && line.endsWith(" PRIVATE KEY-----")) {
                // done!
                break;
            }
            keyData.write(Base64.decode(line));
        }

        byte[] data = keyData.toByteArray();
        if (headers.containsKey("proc-type")) {
            if (password == null) {
                throw new PasswordRequiredException("Private key file is encrypted");
            }
            data = decryptKeyFile(data, headers, password);
        }
        
        PKey pkey = null;
        try {
            pkey = (PKey) keyClass.newInstance();
        } catch (Exception x) {
            throw new SSHException("Internal java error: " + x);
        }
        pkey.buildFromBER(Util.decodeBERSequence(data));
        return pkey;
    }
    
    /**
     * Write a private key to a standard SSH2 key file (ASCII). If a password
     * is given, the key will be encrypted with that password.
     * 
     * @param os the stream to write the key file to
     * @param password (null-ok) a password to use if the file should be
     *     encrypted
     * @throws IOException if there was an error writing the key file
     */
    public abstract void writePrivateKeyToStream (OutputStream os, String password) throws IOException;

    protected void 
    writePrivateKeyToStream (String tag, OutputStream os, BigInteger[] contents, String password)
        throws IOException 
    {
        byte[] data = Util.encodeBERSequence(contents);
        
        StringBuffer sb = new StringBuffer();
        sb.append("-----BEGIN " + tag + " PRIVATE KEY-----\n");
        if (password != null) {
            Crai crai = BaseTransport.getCrai();

            // since we only support one cipher here, just hardcode it. :/
            final String cipherName = "DES-EDE3-CBC";
            final int saltSize = 8;
            
            byte[] salt = new byte[saltSize];
            crai.getPRNG().getBytes(salt);
            data = this.encryptKeyFile(data, cipherName, password, salt);
            
            sb.append("Proc-Type: 4,ENCRYPTED\n");
            sb.append("DEK-Info: " + cipherName + "," + Util.encodeHex(salt).toUpperCase() + "\n");
            sb.append("\n");
        }
     
        // Base64 would break lines at a different length than 64 :(
        String s = Base64.encodeBytes(data, 0, data.length, Base64.DONT_BREAK_LINES);
        while (s.length() > 64) {
            sb.append(s.substring(0, 64));
            sb.append("\n");
            s = s.substring(64);
        }

        sb.append(s);
        sb.append("\n");
        sb.append("-----END " + tag + " PRIVATE KEY-----\n");
     
        os.write(sb.toString().getBytes());
    }
    
    /**
     * Given a password, passphrase, or other human-source key, scramble it
     * through a secure hash into some keyworthy bytes.  This specific
     * algorithm is used for encrypting/decrypting private key files.
     * 
     * @param mac secure hash algorithm to use
     * @param salt data to salt the hash with
     * @param key human-entered password or passphrase
     * @param bytes number of key bytes to generate
     * @return key data
     */
    public static byte[]
    generateKeyBytes (CraiDigest mac, byte[] salt, byte[] key, int bytes)
    {
        byte[] digest = null;
        byte[] keydata = new byte[bytes];
        int offset = 0;
        
        while (bytes > 0) {
            mac.reset();
            if (digest != null) {
                mac.update(digest, 0, digest.length);
            }
            mac.update(key, 0, key.length);
            mac.update(salt, 0, salt.length);
            digest = mac.finish();
            
            int len = (digest.length < bytes) ? digest.length : bytes;
            System.arraycopy(digest, 0, keydata, offset, len);
            offset += len;
            bytes -= len;
        }
        return keydata;
    }

    private static byte[]
    decryptKeyFile (byte[] data, Map headers, String password)
        throws SSHException
    {
        String procType = (String) headers.get("proc-type");
        if (! procType.equals("4,ENCRYPTED")) {
            throw new SSHException("Unknown private key structure '" + procType + "'");
        }
        String[] dek = Util.splitString((String) headers.get("dek-info"), ",");
        if (dek.length != 2) {
            throw new SSHException("Can't parse DEK-info in private key");
        }
        CipherDescription cdesc = (CipherDescription) sCipherMap.get(dek[0]);
        if (cdesc == null) {
            throw new SSHException("Unknown private key cipher '" + dek[0] + "'");
        }
        byte[] salt = null;
        try {
            salt = Util.decodeHex(dek[1]);
        } catch (NumberFormatException x) {
            throw new SSHException("Indecipherable salt in private key");
        }
        
        try {
            Crai crai = BaseTransport.getCrai();
            CraiDigest md5 = crai.makeMD5();
            CraiCipher c = crai.getCipher(cdesc.mAlgorithm);
            byte[] key = generateKeyBytes(md5, salt, password.getBytes(), cdesc.mKeySize);
            c.initDecrypt(key, salt);
            
            byte[] out = new byte[data.length];
            c.process(data, 0, data.length, out, 0);
            return out;
        } catch (CraiException x) {
            throw new SSHException("Unable to initialize cipher '" + cdesc.mAlgorithm + "' due to internal java error: " + x);
        }
    }
    
    private static byte[]
    encryptKeyFile (byte[] data, String cipherName, String password, byte[] salt)
        throws SSHException
    {
        CipherDescription cdesc = (CipherDescription) sCipherMap.get(cipherName);
        if (cdesc == null) {
            throw new SSHException("Unknown private key cipher '" + cipherName + "'");
        }
        
        try {
            Crai crai = BaseTransport.getCrai();
            CraiDigest md5 = crai.makeMD5();
            CraiCipher c = crai.getCipher(cdesc.mAlgorithm);
            byte[] key = generateKeyBytes(md5, salt, password.getBytes(), cdesc.mKeySize);
            c.initEncrypt(key, salt);
            
            if ((data.length % cdesc.mBlockSize) != 0) {
                int n = cdesc.mBlockSize - (data.length % cdesc.mBlockSize);
                byte[] newbuf = new byte[data.length + n];
                System.arraycopy(data, 0, newbuf, 0, data.length);
                // leave the extra bytes as zero.
                data = newbuf;
            }
            
            byte[] out = new byte[data.length];
            c.process(data, 0, data.length, out, 0);
            return out;
        } catch (CraiException x) {
            throw new SSHException("Unable to initialize cipher '" + cdesc.mAlgorithm + "' due to internal java error: " + x);
        }
    }

    
    private static Map sNameMap = new HashMap();
    private static Map sBannerMap = new HashMap();
    private static Map sCipherMap = new HashMap();
    
    static {
        sNameMap.put("ssh-rsa", RSAKey.class);
        sNameMap.put("ssh-dss", DSSKey.class);
        
        sBannerMap.put("RSA", RSAKey.class);
        sBannerMap.put("DSA", DSSKey.class);
        
        sCipherMap.put("DES-EDE3-CBC", new CipherDescription(CraiCipherAlgorithm.DES3_CBC, 24, 8));
    }
}
