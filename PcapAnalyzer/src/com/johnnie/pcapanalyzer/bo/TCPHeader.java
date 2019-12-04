package com.johnnie.pcapanalyzer.bo;

import com.johnnie.pcapanalyzer.utils.DataUtils;

/**
 * TCP 包头：20 字节
 * @author johnnie
 *
 */
public class TCPHeader {
	
	/**
	 * 源端口（2 字节）
	 */
	private short srcPort;
	
	/**
	 * 目的端口（2 字节）
	 */
	private short dstPort;
	
	/**
	 * Sequence Number：发送数据包中的第一个字节的序列号（4 字节）
	 */
	private int seqNum;
	
	/**
	 * 确认序列号（4 字节）
	 */
	private int ackNum;
	
	/**
	 * 数据报头的长度(4 bit) + 保留(4 bit) = 1 byte
	 */
	private byte headerLen;
	
	/**
	 * 标识TCP不同的控制消息(1 字节)
	 */
	private byte flags;
	
	/**
	 * 接收缓冲区的空闲空间，用来告诉TCP连接对端自己能够接收的最大数据长度（2 字节）
	 */
	private short window;
	
	/**
	 * 校验和（2 字节）
	 */
	private short checkSum;
	
	/**
	 * 紧急指针（2 字节）
	 */
	private short urgentPointer;

	public short getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(short srcPort) {
		this.srcPort = srcPort;
	}

	public short getDstPort() {
		return dstPort;
	}

	public void setDstPort(short dstPort) {
		this.dstPort = dstPort;
	}

	public int getSeqNum() {
		return seqNum;
	}

	public void setSeqNum(int seqNum) {
		this.seqNum = seqNum;
	}

	public int getAckNum() {
		return ackNum;
	}

	public void setAckNum(int ackNum) {
		this.ackNum = ackNum;
	}

	public byte getHeaderLen() {
		return headerLen;
	}

	public void setHeaderLen(byte headerLen) {
		this.headerLen = headerLen;
	}

	public byte getFlags() {
		return flags;
	}

	public void setFlags(byte flags) {
		this.flags = flags;
	}

	public short getWindow() {
		return window;
	}

	public void setWindow(short window) {
		this.window = window;
	}

	public short getCheckSum() {
		return checkSum;
	}

	public void setCheckSum(short checkSum) {
		this.checkSum = checkSum;
	}

	public short getUrgentPointer() {
		return urgentPointer;
	}

	public void setUrgentPointer(short urgentPointer) {
		this.urgentPointer = urgentPointer;
	}
	
	public TCPHeader() {}

	@Override
	public String toString() {
		return "TCPHeader [srcPort=" + srcPort
				+ ", dstPort=" + dstPort
				+ ", seqNum=" + seqNum
				+ ", ackNum=" + ackNum
				+ ", headerLen=" + headerLen
				+ ", flags=" + DataUtils.byteToHexString(flags)
				+ ", window=" + window
				+ ", checkSum=" + DataUtils.shortToHexString(checkSum)
				+ ", urgentPointer=" + urgentPointer
				+ "]";
	}
	

}
