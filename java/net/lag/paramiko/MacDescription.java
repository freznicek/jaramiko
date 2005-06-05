/*
 * Created on May 27, 2005
 */

package net.lag.paramiko;

/**
 * Description of HMAC algorithms we understand, what java calls them, and
 * their digest sizes.
 * 
 * @author robey
 */
/* package */ final class MacDescription
{
    public
    MacDescription (String name, int size, int naturalSize)
    {
        mJavaName = name;
        mDigestSize = size;
        mNaturalSize = naturalSize;
    }
    
    public String mJavaName;
    public int mDigestSize;     // bytes
    public int mNaturalSize;    // bytes
}
