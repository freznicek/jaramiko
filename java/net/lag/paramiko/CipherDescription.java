/*
 * Created on May 25, 2005
 */

package net.lag.paramiko;

/**
 * Description of ciphers we understand, what java calls them, and their
 * key/block size parameters.
 * 
 * @author robey
 */
/* package */ final class CipherDescription
{
    public CipherDescription (String j, int k, int b)
    {
        mJavaName = j;
        mKeySize = k;
        mBlockSize = b;
    }

    public String mJavaName;
    public int mKeySize;        // bytes
    public int mBlockSize;      // bytes
}
