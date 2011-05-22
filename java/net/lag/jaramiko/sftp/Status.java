package net.lag.jaramiko.sftp;

public enum Status {
	OK(0),
	EOF(1),
	NoSuchFile(2),
	PermissionDenied(3),
	Failure(4),
	BadMessage(5),
	NoConnection(6),
	ConnectionLost(7),
	OPUnsupported(8);
	
	private int binaryCode;

	Status(int binaryCode) {
		this.binaryCode = binaryCode;
	}
	
	public int getBinaryCode() {
		return this.binaryCode;
	}
}
