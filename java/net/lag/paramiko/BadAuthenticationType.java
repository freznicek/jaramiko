/*
 * Created on May 30, 2005
 */

package net.lag.paramiko;

/**
 * Exception raised when an authentication type (like password) is used, but
 * the server isn't allowing that type.  (It may only allow public-key, for
 * example.)
 * 
 * @author robey
 */
public class BadAuthenticationType
    extends SSHException
{
    /* package */
    BadAuthenticationType (String[] types)
    {
        super("Bad authentication type.");
        mAllowedTypes = types;
    }
    
    /**
     * Return the list of authentication types allowed by the server.  Possible
     * values are: <code>"none"</code>, <code>"password"</code>, and
     * <code>"publickey"</code>.
     * 
     * @return the list of auth types allowed by the server
     */
    public String[]
    getAllowedTypes ()
    {
        return mAllowedTypes;
    }
    
    
    private String[] mAllowedTypes;
    
    private static final long serialVersionUID = 0;
}
