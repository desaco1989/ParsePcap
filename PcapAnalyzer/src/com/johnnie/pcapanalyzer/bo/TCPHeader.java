package com.johnnie.pcapanalyzer.bo;

import com.johnnie.pcapanalyzer.utils.DataUtils;

/**
 * TCP ��ͷ��20 �ֽ�
 * @author johnnie
 *
 */
public class TCPHeader {
	
	/**
	 * Դ�˿ڣ�2 �ֽڣ�
	 */
	private short srcPort;
	
	/**
	 * Ŀ�Ķ˿ڣ�2 �ֽڣ�
	 */
	private short dstPort;
	
	/**
	 * Sequence Number���������ݰ��еĵ�һ���ֽڵ����кţ�4 �ֽڣ�
	 */
	private int seqNum;
	
	/**
	 * ȷ�����кţ�4 �ֽڣ�
	 */
	private int ackNum;
	
	/**
	 * ���ݱ�ͷ�ĳ���(4 bit) + ����(4 bit) = 1 byte
	 */
	private byte headerLen;
	
	/**
	 * ��ʶTCP��ͬ�Ŀ�����Ϣ(1 �ֽ�)
	 */
	private byte flags;
	
	/**
	 * ���ջ������Ŀ��пռ䣬��������TCP���ӶԶ��Լ��ܹ����յ�������ݳ��ȣ�2 �ֽڣ�
	 */
	private short window;
	
	/**
	 * У��ͣ�2 �ֽڣ�
	 */
	private short checkSum;
	
	/**
	 * ����ָ�루2 �ֽڣ�
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
