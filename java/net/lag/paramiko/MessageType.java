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
 * Created on May 8, 2005
 */

package net.lag.paramiko;

/**
 * Constants used by paramiko for SSH2 packet types.
 * 
 * @author robey
 */
/* package */ class MessageType
{
    public static final byte DISCONNECT = 1;
    public static final byte IGNORE = 2;
    public static final byte UNIMPLEMENTED = 3;
    public static final byte DEBUG = 4;
    public static final byte SERVICE_REQUEST = 5;
    public static final byte SERVICE_ACCEPT = 6;
    
    public static final byte KEX_INIT = 20;
    public static final byte NEW_KEYS = 21;
    
    public static final byte KEX_0 = 30;
    public static final byte KEX_1 = 31;
    public static final byte KEX_2 = 32;
    public static final byte KEX_3 = 33;
    public static final byte KEX_4 = 34;

    public static final byte USERAUTH_REQUEST = 50;
    public static final byte USERAUTH_FAILURE = 51;
    public static final byte USERAUTH_SUCCESS = 52;
    public static final byte USERAUTH_BANNER = 53;
    
    public static final byte USERAUTH_PK_OK = 60;
    
    public static final byte GLOBAL_REQUEST = 80;
    public static final byte REQUEST_SUCCESS = 81;
    public static final byte REQUEST_FAILURE = 82;

    public static final byte CHANNEL_OPEN = 90;
    public static final byte CHANNEL_OPEN_SUCCESS = 91;
    public static final byte CHANNEL_OPEN_FAILURE = 92;
    public static final byte CHANNEL_WINDOW_ADJUST = 93;
    public static final byte CHANNEL_DATA = 94;
    public static final byte CHANNEL_EXTENDED_DATA = 95;
    public static final byte CHANNEL_EOF = 96;
    public static final byte CHANNEL_CLOSE = 97;
    public static final byte CHANNEL_REQUEST = 98;
    public static final byte CHANNEL_SUCCESS = 99;
    public static final byte CHANNEL_FAILURE = 100;
    
    
    public static String
    getDescription (byte t)
    {
        switch (t) {
        case DISCONNECT:
            return "disconnect";
        case IGNORE:
            return "ignore";
        case UNIMPLEMENTED:
            return "unimplemented";
        case DEBUG:
            return "debug";
        case SERVICE_REQUEST:
            return "service-request";
        case SERVICE_ACCEPT:
            return "service-accept";
        case KEX_INIT:
            return "kex-init";
        case NEW_KEYS:
            return "new-keys";
        case KEX_0:
            return "kex0";
        case KEX_1:
            return "kex1";
        case KEX_2:
            return "kex2";
        case KEX_3:
            return "kex3";
        case KEX_4:
            return "kex4";
        case USERAUTH_REQUEST:
            return "userauth-request";
        case USERAUTH_FAILURE:
            return "userauth-failure";
        case USERAUTH_SUCCESS:
            return "userauth-success";
        case USERAUTH_BANNER:
            return "userauth-banner";
        case USERAUTH_PK_OK:
            return "userauth-pk-ok";
        case GLOBAL_REQUEST:
            return "global-request";
        case REQUEST_SUCCESS:
            return "request-success";
        case REQUEST_FAILURE:
            return "request-failure";
        case CHANNEL_OPEN:
            return "channel-open";
        case CHANNEL_OPEN_SUCCESS:
            return "channel-open-success";
        case CHANNEL_OPEN_FAILURE:
            return "channel-open-failure";
        case CHANNEL_WINDOW_ADJUST:
            return "channel-window-adjust";
        case CHANNEL_DATA:
            return "channel-data";
        case CHANNEL_EXTENDED_DATA:
            return "channel-extended-data";
        case CHANNEL_EOF:
            return "channel-eof";
        case CHANNEL_CLOSE:
            return "channel-close";
        case CHANNEL_REQUEST:
            return "channel-request";
        case CHANNEL_SUCCESS:
            return "channel-success";
        case CHANNEL_FAILURE:
            return "channel-failure";
        default:
            return "$" + Integer.toString(t);
        }
    }

}