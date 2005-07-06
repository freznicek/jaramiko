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
 * Created on Jul 2, 2005
 */

package net.lag.paramiko;

import java.io.FileInputStream;
import java.util.List;

/**
 * @author robey
 */
public class FakeServer
    implements ServerInterface
{
    public
    FakeServer ()
        throws Exception
    {
        mParanoidDidPassword = false;
        mParanoidDidPublicKey = false;
        mParanoidKey = PKey.readPrivateKeyFromStream(new FileInputStream("test/test_dss.key"), null);
    }

    public int
    checkChannelRequest (String kind, int chanID)
    {
        return ChannelError.SUCCESS;
    }
    
    public String
    getAllowedAuths (String username)
    {
        if (username.equals("slowdive")) {
            return "publickey,password";
        }
        if (username.equals("paranoid")) {
            if (! mParanoidDidPassword && ! mParanoidDidPublicKey) {
                return "publickey,password";
            } else if (mParanoidDidPassword) {
                return "publickey";
            } else {
                return "password";
            }
        }
        return "publickey";
    }
    
    public int
    checkAuthNone (String username)
    {
        return AuthError.FAILED;
    }
    
    public int
    checkAuthPassword (String username, String password)
    {
        if (username.equals("slowdive") && password.equals("pygmalion")) {
            return AuthError.SUCCESS;
        }
        if (username.equals("paranoid") && password.equals("paranoid")) {
            // 2-part auth (even openssh doesn't support this)
            mParanoidDidPassword = true;
            if (mParanoidDidPublicKey) {
                return AuthError.SUCCESS;
            }
            return AuthError.PARTIAL_SUCCESS;
        }
        return AuthError.FAILED;
    }
    
    public int
    checkAuthPublicKey (String username, PKey key)
    {
        if (username.equals("paranoid") && key.equals(mParanoidKey)) {
            // 2-part auth
            mParanoidDidPublicKey = true;
            if (mParanoidDidPassword) {
                return AuthError.SUCCESS;
            }
            return AuthError.PARTIAL_SUCCESS;
        }
        return AuthError.FAILED;
    }

    public List
    checkGlobalRequest (String kind, Message m)
    {
        mGlobalRequest = kind;
        return null;
    }

    public boolean
    checkChannelPTYRequest (Channel c, String term, int width,
                            int height, int pixelWidth,
                            int pixelHeight, String modes)
    {
        return false;
    }

    public boolean
    checkChannelShellRequest (Channel c)
    {
        return true;
    }

    public boolean
    checkChannelExecRequest (Channel c, String command)
    {
        if (! command.equals("yes")) {
            return false;
        }
        return true;
    }

    public boolean
    checkChannelSubsystemRequest (Channel c, String name)
    {
        return false;
    }

    public boolean
    checkChannelWindowChangeRequest (Channel c, int width,
                                     int height, int pixelWidth,
                                     int pixelHeight)
    {
        return false;
    }
    
    
    public boolean mParanoidDidPassword;
    public boolean mParanoidDidPublicKey;
    public PKey mParanoidKey;
    public String mGlobalRequest;
}
