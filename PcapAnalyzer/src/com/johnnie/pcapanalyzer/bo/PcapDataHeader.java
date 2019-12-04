package com.johnnie.pcapanalyzer.bo;

import com.johnnie.pcapanalyzer.utils.DataUtils;

/**
 * Pcap ���ݰ�ͷ
 * @author johnnie
 *
 */
public class PcapDataHeader {
	
	/**
	 * ʱ������룩����¼���ݰ�ץ���ʱ��
	 * ��¼��ʽ�ǴӸ�������ʱ���1970��1��1�� 00:00:00 ��ץ��ʱ������������4���ֽڣ�
	 */
	private int timeS;	
	/**
	 * ʱ�����΢�룩��ץȡ���ݰ�ʱ��΢��ֵ��4���ֽڣ�
	 */
	private int timeMs;						
	/**
	 * ���ݰ����ȣ���ʶ��ץ������ݰ������� pcap �ļ��е�ʵ�ʳ��ȣ����ֽ�Ϊ��λ��4���ֽڣ�
	 */
	private int caplen;
	/**
	 * ���ݰ�ʵ�ʳ��ȣ� ��ץ������ݰ�����ʵ���ȣ�4���ֽڣ�
	 * ����ļ��б��治�����������ݰ�����ô���ֵ����Ҫ��ǰ������ݰ����ȵ�ֵ��
	 */
	private int len;						
	
	public int getTimeS() {
		return timeS;
	}

	public void setTimeS(int timeS) {
		this.timeS = timeS;
	}

	public int getTimeMs() {
		return timeMs;
	}

	public void setTimeMs(int timeMs) {
		this.timeMs = timeMs;
	}

	public int getCaplen() {
		return caplen;
	}

	public void setCaplen(int caplen) {
		this.caplen = caplen;
	}

	public int getLen() {
		return len;
	}

	public void setLen(int len) {
		this.len = len;
	}

	public PcapDataHeader() {}
	
	@Override
	public String toString() {
		return "PcapDataHeader [timeS=" +  DataUtils.intToHexString(timeS)
				+ ", timeMs=" +  DataUtils.intToHexString(timeMs)
				+ ", caplen=" +  caplen
				+ ", len=" +  len
				+ "]";
	}

}
