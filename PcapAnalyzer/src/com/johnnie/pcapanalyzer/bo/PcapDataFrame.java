package com.johnnie.pcapanalyzer.bo;

import com.johnnie.pcapanalyzer.utils.DataUtils;

/**
 * Pcap ���������֡ͷ����̫��֡��14 ���ֽڣ����Բ�������ֱ������
 * @author johnnie
 *
 */
public class PcapDataFrame {
	
	/**
	 * Ŀ�� MAC ��ַ��6 byte
	 */
	private byte[] desMac;
	
	/**
	 * Դ MAC ��ַ��6 byte
	 */
	private byte[] srcMac;
	
	/**
	 * ����֡����:2 �ֽ�
	 */
	private short frameType;

	public byte[] getDesMac() {
		return desMac;
	}

	public void setDesMac(byte[] desMac) {
		this.desMac = desMac;
	}

	public byte[] getSrcMac() {
		return srcMac;
	}

	public void setSrcMac(byte[] srcMac) {
		this.srcMac = srcMac;
	}

	public short getFrameType() {
		return frameType;
	}

	public void setFrameType(short frameType) {
		this.frameType = frameType;
	}
	
	public PcapDataFrame() {}
	
	/**
	 * ���� Wireshark �ĸ�ʽ��ʾ��Ϣ
	 */
	@Override
	public String toString() {
		// frameType �� ʮ��������ʾ
		return "PcapDataFrame [frameType=" + DataUtils.shortToHexString(frameType) + "]";
	}
	
}
