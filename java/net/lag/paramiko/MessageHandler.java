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
    /**
     * Handle an SSH protocol message and return true if the message was
     * understood, or false if it wasn't (and wasn't handled).  This is part
     * of paramiko's internal implementation.
     * 
     * @param ptype message type
     * @param m message
     * @return true if the message was handled; false otherwise
     * @throws IOException if an exception occurred
     */
    public boolean handleMessage (byte ptype, Message m) throws IOException;
}
