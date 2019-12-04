package com.johnnie.pcapanalyzer.bo;

import com.johnnie.pcapanalyzer.utils.DataUtils;

/**
 * Pcap 文件头结构
 * @author johnnie
 *
 */
public class PcapFileHeader {

	private int magic;					// 标识位，这个标识位的值是16进制的 0xa1b2c3d4（4个字节）
	private short magorVersion;		// 主版本号（2个字节）
	private short minorVersion;		// 副版本号（2个字节）
	private int timezone;				// 区域时间（4个字节）
	private int sigflags;				// 精确时间戳（4个字节）
	private int snaplen;				// 数据包最大长度（4个字节）
	private int linktype;				// 链路层类型（4个字节）
	
	public int getMagic() {
		return magic;
	}

	public void setMagic(int magic) {
		this.magic = magic;
	}

	public short getMagorVersion() {
		return magorVersion;
	}

	public void setMagorVersion(short magorVersion) {
		this.magorVersion = magorVersion;
	}

	public short getMinorVersion() {
		return minorVersion;
	}

	public void setMinorVersion(short minorVersion) {
		this.minorVersion = minorVersion;
	}

	public int getTimezone() {
		return timezone;
	}

	public void setTimezone(int timezone) {
		this.timezone = timezone;
	}

	public int getSigflags() {
		return sigflags;
	}

	public void setSigflags(int sigflags) {
		this.sigflags = sigflags;
	}

	public int getSnaplen() {
		return snaplen;
	}

	public void setSnaplen(int snaplen) {
		this.snaplen = snaplen;
	}

	public int getLinktype() {
		return linktype;
	}

	public void setLinktype(int linktype) {
		this.linktype = linktype;
	}

	public PcapFileHeader() {}
	
	public PcapFileHeader(int magic, short magorVersion, short minorVersion,
			int timezone, int sigflags, int snaplen, int linktype) {
		this.magic = magic;
		this.magorVersion = magorVersion;
		this.minorVersion = minorVersion;
		this.timezone = timezone;
		this.sigflags = sigflags;
		this.snaplen = snaplen;
		this.linktype = linktype;
	}
	
	@Override
	public String toString() {
		return "PcapFileHeader [magic=" + DataUtils.intToHexString(magic)
				+ ", magorVersion=" + DataUtils.shortToHexString(magorVersion)
				+ ", minorVersion=" + DataUtils.shortToHexString(minorVersion)
				+ ", timezone=" + DataUtils.intToHexString(timezone)
				+ ", sigflags=" +  DataUtils.intToHexString(sigflags)
				+ ", snaplen=" +  DataUtils.intToHexString(snaplen)
				+ ", linktype=" +  DataUtils.intToHexString(linktype)
				+ "]";
	}
	
}
