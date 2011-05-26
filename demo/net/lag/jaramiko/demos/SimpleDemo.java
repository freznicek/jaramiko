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

import java.io.Console;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOError;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.Map;

import net.lag.jaramiko.ClientTransport;
import net.lag.jaramiko.Channel;
import net.lag.jaramiko.HostKeys;
import net.lag.jaramiko.PKey;
import net.lag.jaramiko.SSHException;
import net.lag.jaramiko.sftp.Client;

public class SimpleDemo {
    private static final int SSH_PORT = 22;

    private static ClientTransport connect(String servername, PKey hostkey,
                                           String username, String password)
                                           throws IOException, SSHException {

        return connect(servername, hostkey, username, password, 15000);
    }

    private static ClientTransport connect(String servername, PKey hostkey,
                                           String username, String password,
                                           int timeout)
                                           throws IOException, SSHException {


        ClientTransport connection = null;

        notice("Connecting...");
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(servername, SSH_PORT));
        connection = new ClientTransport(socket);

        notice("Negotiating...");
        connection.start(hostkey, timeout);

        notice("Authenticating...");
        String[] next = connection.authPassword(username, password, timeout);

        if (next.length > 0) {
            notice("Authentication too complex: %s", Arrays.asList(next));

            throw new SSHException("Authentication too complex");
        }

        return connection;
    }

    private static void executeCommand(String servername, PKey hostkey,
                                       String username, String password,
                                       String command) {

        executeCommand(servername, hostkey, username, password, command, 15000);
    }

    private static void executeCommand(String servername, PKey hostkey,
                                       String username, String password,
                                       String command, int timeout) {

        ClientTransport connection = null;

        try {
            connection = connect(servername, hostkey, username, password,
                                timeout);

            notice("Executing command \"%s\"...", command);
            Channel channel = connection.openSession(timeout);
            channel.execCommand(command, timeout);

            InputStream input = channel.getInputStream();

            byte[] buffer = new byte[4096];
            while (true) {
                try {
                    int n = input.read(buffer);
                    if (n < 0) break;
                    else if (n > 0) System.out.write(buffer, 0, n);
                } catch (IOException e) {
                    notice("Connection stopped abruptly %s", e.getMessage());
                    break;
                }
            }

            channel.close();
            notice("\nDone.");
        } catch (SSHException e) {
            notice("Problem with SSH: %s", e.getMessage());
        } catch (IOException e) {
            notice("Problem communicating with server \"%s\"", servername);
        } finally {
            if (connection != null) connection.close();
        }
    }

    private static void executeTransfer(String servername, PKey hostkey,
                                        String username, String password,
                                        String filename) {

        executeTransfer(servername, hostkey, username, password, filename,
                        15000);
    }

    private static void executeTransfer(String servername, PKey hostkey,
                                        String username, String password,
                                        String filename, int timeout) {

        ClientTransport connection = null;

        try {
            connection = connect(servername, hostkey, username, password,
                                timeout);

            notice("Executing transfer...");

            Client sftp = Client.fromTransport(connection);
            try {
                for (String name : sftp.listdir("/")) {
                    notice("Found root directory: %s", name);
                }

                notice("Opening file: %s", filename);
                InputStream stream = sftp.openInputStream(filename);

                try {
                    BufferedReader reader = new BufferedReader(
                                                new InputStreamReader(stream));


                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println(line);
                    }
                } finally {
                    stream.close();
                }
            } finally {
                sftp.close();
            }

            notice("\nDone.");
        } catch (SSHException e) {
            notice("Problem with SSH %s", e.getMessage());
        } catch (IOException e) {
            notice("Problem communicating with server \"%s\"", servername);
        } finally {
            if (connection != null) connection.close();
        }
    }

    private static void giveup() {
        notice("Looks like you gave up! Bye.");
        System.exit(0);
    }

    private static void notice(String format, Object... args) {
        System.out.println(String.format(format, args));
    }

    private static String readline(BufferedReader reader) {
        try {
            return reader.readLine();
        } catch (IOException e) {
            return null;
        }
    }

    public static void main(String[] args) {
        BufferedReader in = new BufferedReader(
                                    new InputStreamReader(System.in));

        notice("Welcome! Do you want to try SSH or SFTP?: ");
        String choice = null;
        do {
            if (choice != null) notice("Please, SSH or SFTP?: ");
            choice = readline(in);

            if (choice != null) choice = choice.toLowerCase();
        } while (choice != null && !choice.equals("ssh")
                 && !choice.equals("sftp"));

        Map<String, String> env = System.getenv();
        String username = env.get("USER");
        String home = env.get("HOME");
        String password = null;
        String server = null;
        String userinput = null;

        if (choice == null) giveup();
        else if (choice.equals("ssh")) {
            notice("What command do you want to run?: ");
            userinput = readline(in);

            if (userinput == null) giveup();
            else if (userinput.trim().length() == 0) {
                userinput = "ls";
                notice("That's not a good command, let's try \"%s\"",
                       userinput);
            }
        } else {
            notice("What file to you want to read?: ");
            userinput = readline(in);

            if (userinput == null) giveup();
            else if (userinput.trim().length() == 0) {
                userinput = "/etc/hosts";
                notice("That's not a good file, let's try \"%s\"", userinput);
            }
        }

        notice("Have a server in mind? (localhost): ");
        server = readline(in);

        if (server == null) giveup();
        else if (server.trim().length() == 0) {
            server = "localhost";
            notice("Ok, looks like we are going to use \"%s\"", server);
        }

        do {
            if (username != null) notice("username (%s): ", username);
            else notice("username: ");

            String line = readline(in);
            if (line == null) giveup();
            else if (line.trim().length() > 0) username = line;
        } while (username == null);

        Console console = System.console();
        if (console != null) {
            char[] pass = null;

            try {
                pass = console.readPassword("Password: ");
            } catch (IOError e) {
                giveup();
            }

            if (pass == null) giveup();
            else password = new String(pass);
        } else {
            notice("Your password will be repeated in plain text!\nPassword: ");
            password = readline(in);

            if (password == null) giveup();
        }

        File hostkeys = null;
        // This is a *nix location anyways
        if (home != null) hostkeys = new File(home, ".ssh/known_hosts");

        PKey hostkey = null;
        if (hostkeys != null && hostkeys.isFile()) {
            try {
                HostKeys keys = new HostKeys();
                keys.load(new FileInputStream(hostkeys.getPath()));
                Map<String, PKey> keymap = keys.lookup(server);

                if (keymap.size() == 0)
                    notice("Could not find host key for \"%s\"", server);

                // Use the first key
                else hostkey = keymap.values().iterator().next();

            } catch (IOException e) {
                notice("Could not open the host keys file! %s", e.getMessage());
            }
        }

        if (hostkey == null) {
            notice("No keys were found! And no checking will be done.");

            String line = "";
            do {
                notice("Continue? (y/n): ");
                line = readline(in);

                if (line != null) line.toLowerCase();
                if (line.startsWith("n")) {
                    notice("Bye.");
                    System.exit(0);
                }
            } while (!line.startsWith("y"));
        }

        if (choice.equals("ssh"))
            executeCommand(server, hostkey, username, password, userinput);
        else
            executeTransfer(server, hostkey, username, password, userinput);
    }
}
