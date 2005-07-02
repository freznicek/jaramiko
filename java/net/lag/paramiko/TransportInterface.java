/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
 *
 * Paramiko is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Paramiko; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 * 
 * 
 * Created on May 14, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.math.BigInteger;

/**
 * This makes it easier to unit-test the Kex implementations, by letting the
 * Transport interface be easily stubbed out.
 * 
 * @author robey
 */
/* package */ interface TransportInterface
{
    public byte[] getSessionID();
    public boolean inServerMode ();    
    public void expectPacket (byte ptype);
    public void saveException (IOException x);
    public void sendMessage (Message m) throws IOException;
    public void sendUserMessage (Message m, int timeout_ms) throws IOException;
    public String getLocalVersion ();
    public String getRemoteVersion ();
    public byte[] getLocalKexInit ();
    public byte[] getRemoteKexInit ();
    public PKey getServerKey ();
    public void setKH (BigInteger k, byte[] h);
    public void verifyKey (byte[] hostKey, byte[] sig) throws SSHException;
    public void registerMessageHandler (byte ptype, MessageHandler handler);
    public void activateOutbound () throws IOException;
    public void unlinkChannel (int chanID);
    public void close ();
}
