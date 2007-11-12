/*
 * Copyright (C) 2005-2007 Robey Pointer <robey@lag.net>
 *
 * This file is part of jaramiko.
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

package net.lag.jaramiko.demos;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;

import net.lag.jaramiko.Channel;
import net.lag.jaramiko.ClientTransport;
import net.lag.jaramiko.HostKeys;
import net.lag.jaramiko.PKey;


public class SimpleDemo
{
    private static final int SSH_PORT = 22;
    

    private static void
    executeCommand (String serverName, PKey hostkey, String username, String password, String command)
    {
        ClientTransport transport = null;
        
        try {
            System.out.println("--- Connecting...");
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(serverName, SSH_PORT));
            transport = new ClientTransport(socket);
            System.out.println("--- Negotiating...");
            transport.start(hostkey, 15000);
            System.out.println("--- Authenticating...");
            String[] next = transport.authPassword(username, password, 15000);
            if (next.length > 0) {
                throw new IOException("Auth too complex: " + Arrays.asList(next));
            }
            System.out.println("--- Executing...");
            Channel channel = transport.openSession(15000);
            channel.execCommand(command, 15000);
            InputStream chanIn = channel.getInputStream();
            byte[] buffer = new byte[512];
            while (true) {
                try {
                    int n = chanIn.read(buffer);
                    if (n < 0) {
                        break;
                    }
                    if (n > 0) {
                        System.out.write(buffer, 0, n);
                    }
                } catch (IOException x) {
                    break;
                }
            }
            channel.close();
            System.out.println();
            System.out.println("--- Done.");
        } catch (IOException x) {
            System.out.println("I/O exception: " + x);
        } finally {
            if (transport != null) {
                transport.close();
            }
        }
    }
    
    public static void
    main (String[] args)
        throws Exception
    {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        
        System.out.println();
        System.out.println("This demo will connect to an SSH server, login with a username and");
        System.out.println("password, and execute a single command.");
        System.out.println();

        System.out.print("Server [localhost]: ");
        String serverName = in.readLine();
        if (serverName.length() == 0) {
            serverName = "localhost";
        }
        System.out.print("Username: ");
        String username = in.readLine();
        String password = new String(PasswordInput.getPassword(System.in, "Password: "));
        System.out.print("Hostkeys file location [/home/" + username + "/.ssh/known_hosts]: ");
        String hostkeysFilename = in.readLine();
        if (hostkeysFilename.length() == 0) {
            hostkeysFilename = "/home/" + username + "/.ssh/known_hosts";
        }
        System.out.print("Command [ls]: ");
        String command = in.readLine();
        if (command.length() == 0) {
            command = "ls";
        }
        
        PKey hostkey = null;
        try {
            FileInputStream hostkeysFile = new FileInputStream(hostkeysFilename);
            HostKeys keys = new HostKeys();
            keys.load(hostkeysFile);
            Map keymap = keys.lookup(serverName);
            if (keymap.size() == 0) {
                System.out.println("!!! Couldn't find hostkey for " + serverName);
            } else {
                // just grab the first one.
                hostkey = (PKey) keymap.values().iterator().next();
            }
        } catch (IOException x) {
            System.out.println("!!! Couldn't open hostkeys file: " + x);
            System.out.println("!!! Therefore, no host key checking will be done, which is insecure.");
        }
        
        executeCommand(serverName, hostkey, username, password, command);
    }
}
