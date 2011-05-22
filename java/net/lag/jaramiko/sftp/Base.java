package net.lag.jaramiko.sftp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.lag.jaramiko.Channel;
import net.lag.jaramiko.Message;

public class Base {
    protected Channel channel;
    public Base(Channel channel) {
        this.channel = channel;
    }

    public Channel getChannel() {
        return this.channel;
    }

    protected void sendPacket(Command command, Message message) throws IOException {
        byte[] data = message.toByteArray();
        OutputStream stream = channel.getOutputStream();
        // FIXME do this in 1 step.
        int len = data.length + 1;
        stream.write((len >> 24) & 0xFF);
        stream.write((len >> 16) & 0xFF);
        stream.write((len >> 8) & 0xFF);
        stream.write((len >> 0) & 0xFF);
        stream.write(command.getBinaryCode());
        stream.write(data);
        stream.flush();
    }

    /** @return the packet as a message. First byte is the result command (result type).
     * @throws IOException */
    protected Message readPacket() throws IOException {
        InputStream stream = channel.getInputStream();
        byte[] lenBytes = new byte[4];
        if (stream.read(lenBytes) != 4) {
            throw new RuntimeException("unexpected end of file on SFTP channel."); // FIXME.
        }

        if (lenBytes[0] != 0) {
            throw new RuntimeException("unexpected data byte."); // FIXME
        }

        int len = (((int) lenBytes[0] & 0xff) << 24) |
                  (((int) lenBytes[1] & 0xff) << 16) |
                  (((int) lenBytes[2] & 0xff) << 8) |
                  ((int) lenBytes[3] & 0xff);

        /*int resultType = stream.read();
        if (resultType == -1) {
            throw new RuntimeException("unexpected end of file on SFTP.");
        }*/

        byte[] data = new byte[len];
        if (stream.read(data) != len) {
            throw new RuntimeException("unexpected end of file on SFTP channel."); // FIXME.
        }

        return new Message(data);
    }

}
