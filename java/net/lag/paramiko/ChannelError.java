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
 * Created on Jun 20, 2005
 */

package net.lag.paramiko;


/**
 * Error codes returned by an SSH2 server when it rejects a request to open
 * a new channel.
 * 
 * @author robey
 */
public final class ChannelError
{
    private
    ChannelError ()
    {
        // forbid
    }
    
    
    public static final int SUCCESS = 0;
    public static final int ADMINISTRATIVELY_PROHIBITED = 1;
    public static final int CONNECT_FAILED = 2;
    public static final int UNKNOWN_CHANNEL_TYPE = 3;
    public static final int RESOURCE_SHORTAGE = 4;
}
