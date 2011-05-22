package net.lag.jaramiko.sftp;

public enum Command {
    Init(1),
    Version(2),
    Open(3),
    Close(4),
    Read(5),
    Write(6),
    LSTAT(7),
    FSTAT(8),
    SetSTAT(9),
    FSetSTAT(10),
    OpenDir(11),
    ReadDir(12),
    Remove(13),
    MKDir(14),
    RMDir(15),
    RealPath(16),
    STAT(17),
    Rename(18),
    ReadLink(19),
    Symlink(20),

    Status(101),
    Handle(102),
    Data(103),
    Name(104),
    Attrs(105),

    Extended(200),
    ExtendedReply(201);

    private int binaryCode;
    Command(int binaryCode) {
        this.binaryCode = binaryCode;
    }

    int getBinaryCode() {
        return this.binaryCode;
    }
}
