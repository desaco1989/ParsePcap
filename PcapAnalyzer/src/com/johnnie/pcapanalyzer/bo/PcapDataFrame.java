package com.johnnie.pcapanalyzer.bo;

import com.johnnie.pcapanalyzer.utils.DataUtils;

/**
 * Pcap 捕获的数据帧头：以太网帧，14 个字节，可以不做处理，直接跳过
 * @author johnnie
 *
 */
public class PcapDataFrame {
	
	/**
	 * 目的 MAC 地址：6 byte
	 */
	private byte[] desMac;
	
	/**
	 * 源 MAC 地址：6 byte
	 */
	private byte[] srcMac;
	
	/**
	 * 数据帧类型:2 字节
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
	 * 按照 Wireshark 的格式显示信息
	 */
	@Override
	public String toString() {
		// frameType 以 十六进制显示
		return "PcapDataFrame [frameType=" + DataUtils.shortToHexString(frameType) + "]";
	}
	
}
