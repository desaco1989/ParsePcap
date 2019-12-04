package com.johnnie.pcapanalyzer.bo;

import com.johnnie.pcapanalyzer.utils.DataUtils;

/**
 * IP ���ݱ�ͷ
 * @author johnnie
 *
 */
public class IPHeader {

	/**
	 * Э��汾��(4 bit)����ͷ����(4bit) =��1 �ֽڣ�
	 * �汾��(Version):һ���ֵΪ0100��IPv4����0110��IPv6��
	 * IP��ͷ��С����Ϊ20�ֽ�
	 */
	private byte varHLen;
	
	/**
	 * Type of  Service���������ͣ���1 �ֽڣ�
	 */
	private byte tos;
	
	/**
	 * �ܳ��ȣ�2 �ֽڣ�
	 */
	private short totalLen;
	
	/**
	 * ��ʶ��2 �ֽڣ�
	 */
	private short id;
	
	/**
	 * ��־��ƫ������2 �ֽڣ�
	 */
	private short flagSegment;
	
	/**
	 * Time to Live���������ڣ�1 �ֽڣ�
	 */
	private byte ttl;
	
	/**
	 * Э�����ͣ�1 �ֽڣ�
	 */
	private byte protocol;
	
	/**
	 * ͷ��У��ͣ�2 �ֽڣ�
	 */
	private short checkSum;
	
	/**
	 * Դ IP��4 �ֽڣ�
	 */
	private int srcIP;
	
	/**
	 * Ŀ�� IP��4 �ֽڣ�
	 */
	private int dstIP;

	public byte getVarHLen() {
		return varHLen;
	}

	public void setVarHLen(byte varHLen) {
		this.varHLen = varHLen;
	}

	public byte getTos() {
		return tos;
	}

	public void setTos(byte tos) {
		this.tos = tos;
	}

	public short getTotalLen() {
		return totalLen;
	}

	public void setTotalLen(short totalLen) {
		this.totalLen = totalLen;
	}

	public short getId() {
		return id;
	}

	public void setId(short id) {
		this.id = id;
	}

	public short getFlagSegment() {
		return flagSegment;
	}

	public void setFlagSegment(short flagSegment) {
		this.flagSegment = flagSegment;
	}

	public byte getTtl() {
		return ttl;
	}

	public void setTtl(byte ttl) {
		this.ttl = ttl;
	}

	public byte getProtocol() {
		return protocol;
	}

	public void setProtocol(byte protocol) {
		this.protocol = protocol;
	}

	public short getCheckSum() {
		return checkSum;
	}

	public void setCheckSum(short checkSum) {
		this.checkSum = checkSum;
	}

	public int getSrcIP() {
		return srcIP;
	}

	public void setSrcIP(int srcIP) {
		this.srcIP = srcIP;
	}

	public int getDstIP() {
		return dstIP;
	}

	public void setDstIP(int dstIP) {
		this.dstIP = dstIP;
	}
	
	public IPHeader() {	}
	
	@Override
	public String toString() {
		return "IPHeader [varHLen=" + DataUtils.byteToHexString(varHLen)
				+ ", tos=" + DataUtils.byteToHexString(tos)
				+ ", totalLen=" + totalLen
				+ ", id=" + DataUtils.shortToHexString(id)
				+ ", flagSegment=" + DataUtils.shortToHexString(flagSegment)
				+ ", ttl=" + ttl
				+ ", protocol=" + protocol
				+ ", checkSum=" + DataUtils.shortToHexString(checkSum)
				+ ", srcIP=" + DataUtils.intToHexString(srcIP)
				+ ", dstIP=" + DataUtils.intToHexString(dstIP)
				+ "]";
	}
}
