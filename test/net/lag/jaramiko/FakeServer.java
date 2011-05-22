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
 */

package net.lag.jaramiko;

import java.io.FileInputStream;
import java.util.List;

/**
 * ServerInterface implementation that just records which methods were called
 * and what parameters were passed in.
 */
public class FakeServer implements ServerInterface {
    public FakeServer() throws Exception {
        mParanoidDidPassword = false;
        mParanoidDidPublicKey = false;
        mParanoidKey = PKey.readPrivateKeyFromStream(new FileInputStream(
                "test/test_dss.key"), null);
    }

    @Override
    public int checkChannelRequest(String kind, int chanID) {
        if (kind.equals("bogus")) {
            return ChannelError.ADMINISTRATIVELY_PROHIBITED;
        }
        return ChannelError.SUCCESS;
    }

    @Override
    public String getAllowedAuths(String username) {
        if (username.equals("slowdive")) {
            return "publickey,password";
        }
        if (username.equals("paranoid")) {
            if (!mParanoidDidPassword && !mParanoidDidPublicKey) {
                return "publickey,password";
            } else if (mParanoidDidPassword) {
                return "publickey";
            } else {
                return "password";
            }
        }
        if (username.equals("commie")) {
            return "keyboard-interactive";
        }
        return "publickey";
    }

    @Override
    public int checkAuthNone(String username) {
        return AuthError.FAILED;
    }

    @Override
    public int checkAuthPassword(String username, String password) {
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

    @Override
    public int checkAuthPublicKey(String username, PKey key) {
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

    @Override
    public InteractiveQuery checkAuthInteractive(String username,
            String[] methods) {
        if (username.equals("commie")) {
            mUsername = username;
            InteractiveQuery query = new InteractiveQuery();
            query.title = "password";
            query.instructions = "Please enter a password.";
            query.prompts = new InteractiveQuery.Prompt[1];
            query.prompts[0] = new InteractiveQuery.Prompt();
            query.prompts[0].text = "Password";
            query.prompts[0].echoResponse = false;
            return query;
        }
        return null;
    }

    @Override
    public int checkAuthInteractiveResponse(String[] responses) {
        if (mUsername.equals("commie")) {
            if ((responses.length == 1) && responses[0].equals("cat")) {
                return AuthError.SUCCESS;
            }
        }
        return AuthError.FAILED;
    }

    @Override
    public List checkGlobalRequest(String kind, Message m) {
        mGlobalRequest = kind;
        return null;
    }

    @Override
    public boolean checkChannelPTYRequest(Channel c, String term, int width,
            int height, int pixelWidth, int pixelHeight, TerminalModes modes) {
        mPTYTerm = term;
        mPTYWidth = width;
        mPTYHeight = height;
        mPTYModes = modes;
        return true;
    }

    @Override
    public boolean checkChannelShellRequest(Channel c) {
        return true;
    }

    @Override
    public boolean checkChannelExecRequest(Channel c, String command) {
        if (!command.equals("yes")) {
            return false;
        }
        return true;
    }

    @Override
    public boolean checkChannelSubsystemRequest(Channel c, String name) {
        return false;
    }

    @Override
    public boolean checkChannelWindowChangeRequest(Channel c, int width,
            int height, int pixelWidth, int pixelHeight) {
        return false;
    }

    public boolean mParanoidDidPassword;
    public boolean mParanoidDidPublicKey;
    public PKey mParanoidKey;
    public String mGlobalRequest;
    public String mUsername;

    public String mPTYTerm;
    public int mPTYWidth;
    public int mPTYHeight;
    public TerminalModes mPTYModes;
}
