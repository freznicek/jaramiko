/* 
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 * Created on Jul 2, 2005
 */

package net.lag.jaramiko;

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
