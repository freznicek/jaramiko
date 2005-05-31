/*
 * Created on May 30, 2005
 */

package net.lag.paramiko;

/**
 * Indicates an authentication result that is successful so far, but needs to
 * continue with further steps (internal library use, not exposed).
 * 
 * @author robey
 */
/* package */ class PartialAuthentication
    extends SSHException
{
    public
    PartialAuthentication (String[] authList)
    {
        super("PartialAuthentication");
        mAuthList = authList;
    }
    
    public String[]
    getAllowedTypes ()
    {
        return mAuthList;
    }
    
    
    private String[] mAuthList;
    
    private static final long serialVersionUID = 0;
}
