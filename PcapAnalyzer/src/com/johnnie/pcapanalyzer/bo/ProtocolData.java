package com.johnnie.pcapanalyzer.bo;

/**
 * 协议数据，五元组
 * @author johnnie
 *
 */
public class ProtocolData {

	String srcIP;										// 源 IP
	String desIP;										// 目的 IP
	
	String srcPort;										// 源端口
	String desPort;										// 目的端口
	
	ProtocolType protocolType = ProtocolType.OTHER;		// 协议类型

	public String getSrcIP() {
		return srcIP;
	}

	public void setSrcIP(String srcIP) {
		this.srcIP = srcIP;
	}

	public String getDesIP() {
		return desIP;
	}

	public void setDesIP(String desIP) {
		this.desIP = desIP;
	}

	public String getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(String srcPort) {
		this.srcPort = srcPort;
	}

	public String getDesPort() {
		return desPort;
	}

	public void setDesPort(String desPort) {
		this.desPort = desPort;
	}

	public ProtocolType getProtocolType() {
		return protocolType;
	}

	public void setProtocolType(ProtocolType protocolType) {
		this.protocolType = protocolType;
	}

	public ProtocolData() {
		// TODO Auto-generated constructor stub
	}

	public ProtocolData(String srcIP, String desIP, String srcPort,
			String desPort, ProtocolType protocolType) {
		this.srcIP = srcIP;
		this.desIP = desIP;
		this.srcPort = srcPort;
		this.desPort = desPort;
		this.protocolType = protocolType;
	}

	@Override
	public String toString() {
		return "ProtocolData [srcIP=" + srcIP
				+ ", desIP=" + desIP
				+ ", srcPort=" + srcPort
				+ ", desPort=" + desPort
				+ ", protocolType=" + protocolType
				+ "]";
	}

}
