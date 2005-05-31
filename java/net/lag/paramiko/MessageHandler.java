/*
 * Created on May 30, 2005
 */

package net.lag.paramiko;

import java.io.IOException;

/**
 * Handler for specific message types in the SSH2 protocol.  This is used to
 * split up handling into sub-components of similar functionality, instead of
 * having one huge Transport class.
 * 
 * @author robey
 */
/* package */ interface MessageHandler
{
    public boolean handleMessage (byte ptype, Message m) throws IOException;
}
