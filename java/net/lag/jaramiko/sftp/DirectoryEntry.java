package net.lag.jaramiko.sftp;

import net.lag.jaramiko.Message;

public class DirectoryEntry implements Comparable<DirectoryEntry> {
    private String longname;
    private String filename;
    private Attributes attributes;

    public DirectoryEntry(String filename) {
        super();
        this.filename = filename;
    }
    public String getLongname() {
        return longname;
    }
    public void setLongname(String longName) {
        this.longname = longName;
    }
    public String getFilename() {
        return filename;
    }
    public void setFilename(String fileName) {
        this.filename = fileName;
    }
    public Attributes getAttributes() {
        return attributes;
    }
    public void setAttributes(Attributes attributes) {
        this.attributes = attributes;
    }

    public static DirectoryEntry fromMessage(Message message) {
        String filename = message.getString();
        DirectoryEntry result = new DirectoryEntry(filename);
        result.setLongname(message.getString());
        result.setAttributes(Attributes.fromMessage(message));
        return result;
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return this.filename; //  + " " + this.attributes.toString();
    }

    @Override
    public int compareTo(DirectoryEntry o) {
        int result = this.filename.compareTo(o.filename);
        if (result == 0) {
            result = this.longname.compareTo(o.longname);
            if (result == 0) {
                result = this.attributes.compareTo(o.attributes);
            }
        }
        return result;
    }

}
