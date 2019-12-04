package com.johnnie.pcapanalyzer.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;

import com.johnnie.pcapanalyzer.bo.IPHeader;
import com.johnnie.pcapanalyzer.bo.PcapDataFrame;
import com.johnnie.pcapanalyzer.bo.PcapDataHeader;
import com.johnnie.pcapanalyzer.bo.PcapFileHeader;
import com.johnnie.pcapanalyzer.bo.PcapStruct;
import com.johnnie.pcapanalyzer.bo.ProtocolData;
import com.johnnie.pcapanalyzer.bo.ProtocolType;
import com.johnnie.pcapanalyzer.bo.TCPHeader;
import com.johnnie.pcapanalyzer.bo.UDPHeader;
import com.johnnie.pcapanalyzer.utils.DataUtils;
import com.johnnie.pcapanalyzer.utils.FileUtils;
import com.johnnie.pcapanalyzer.utils.LogUtils;

/**
 * Pcap �ļ�����������
 * @author johnnie
 *
 */
public class PcapParser extends Observable {

	private File pcap;
	private String savePath;

	private PcapStruct struct;
	private ProtocolData protocolData;
	private IPHeader ipHeader;
	private TCPHeader tcpHeader;
	private UDPHeader udpHeader;
	
	private List<String[]> datas = new ArrayList<String[]>();
	private List<String> filenames = new ArrayList<String>();
	
	private byte[] file_header = new byte[24];
	private byte[] data_header = new byte[16];
	private byte[] content;
//	private byte[] ip_content;
//	private byte[] tcp_content;
//	private byte[] udp_content;
	
	private int data_offset = 0;			// ���ݸ�����Ϣ���ڿ�ʼλ��
	private byte[] data_content;			// ���ݰ������ݸ���
	
	public PcapParser (File pcap, File outDir) {
		this.pcap = pcap;
		this.savePath = outDir.getAbsolutePath();
	}

	public boolean parse () {
		boolean rs = true;
		struct = new PcapStruct();
		List<PcapDataHeader> dataHeaders = new ArrayList<PcapDataHeader>();
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(pcap);
			int m = fis.read(file_header);
			if (m > 0) {

				PcapFileHeader fileHeader = parseFileHeader(file_header);
				
				if (fileHeader == null) {
					LogUtils.printObj("fileHeader", "null");
				}
				struct.setFileHeader(fileHeader);

				while (m > 0) {
					m = fis.read(data_header);
					PcapDataHeader dataHeader = parseDataHeader(data_header);
					dataHeaders.add(dataHeader);

					content = new byte[dataHeader.getCaplen()];
//					LogUtils.printObj("content.length", content.length);
					m = fis.read(content);

					protocolData = new ProtocolData();
					boolean isDone = parseContent();
					if (isDone) {
						break;
					}

					createFiles(protocolData);
					
//					LogUtils.printObjInfo(protocolData);
//					LogUtils.printObj("--------------------------------------");
				}

				rs = true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			FileUtils.closeStream(fis, null);
		}

		return rs;
	}

	/**
	 * ��ȡ pcap �ļ�ͷ
	 */
	public PcapFileHeader parseFileHeader(byte[] file_header) throws IOException {
		PcapFileHeader fileHeader = new PcapFileHeader();
		byte[] buff_4 = new byte[4];	// 4 �ֽڵ�����
		byte[] buff_2 = new byte[2];	// 2 �ֽڵ�����

		int offset = 0;
		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int magic = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setMagic(magic);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short magorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMagorVersion(magorVersion);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short minorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMinorVersion(minorVersion);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int timezone = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setTimezone(timezone);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int sigflags = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSigflags(sigflags);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int snaplen = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSnaplen(snaplen);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int linktype = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setLinktype(linktype);

//		LogUtils.printObjInfo(fileHeader);

		return fileHeader;
	}

	/**
	 * ��ȡ���ݰ�ͷ
	 */
	public PcapDataHeader parseDataHeader(byte[] data_header){
		byte[] buff_4 = new byte[4];
		PcapDataHeader dataHeader = new PcapDataHeader();
		int offset = 0;
		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeS = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setTimeS(timeS);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeMs = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setTimeMs(timeMs);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		// ����������תΪ int
		DataUtils.reverseByteArray(buff_4);
		int caplen = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setCaplen(caplen);
//		LogUtils.printObj("���ݰ�ʵ�ʳ���", dataHeader.getCaplen());

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		//		int len = DataUtils.byteArrayToInt(buff_4);
		DataUtils.reverseByteArray(buff_4);
		int len = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setLen(len);

//		LogUtils.printObjInfo(dataHeader);

		return dataHeader;
	}

	/**
	 * ��������
	 */
	private boolean parseContent() {
		// 1. ��ȡ��̫������֡
		readPcapDataFrame(content);
		// 2. ��ȡ IP
		ipHeader = readIPHeader(content);
		if (ipHeader == null) {							// �� ip Ϊ null ʱ�������
			return true;
		}

		int offset = 14;							// ��̫������֡����
		offset += 20;

		// 3. ���� protocol ���ͽ��з���
		String protocol = ipHeader.getProtocol() + "";
		if (ProtocolType.TCP.getType().equals(protocol)) {
			protocolData.setProtocolType(ProtocolType.TCP);
			tcpHeader = readTCPHeader(content, offset);
		} else if (ProtocolType.UDP.getType().equals(protocol)) {
			protocolData.setProtocolType(ProtocolType.UDP);
			udpHeader = readUDPHeader(content, offset);
		} else {
//			LogUtils.printObj("��������Э������ݰ�");
		}

		return false;
	}

	private TCPHeader readTCPHeader(byte[] content2, int offset) {
		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];

		TCPHeader tcp = new TCPHeader();

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
//			LogUtils.printByteToBinaryStr("TCP: buff_2[" + i + "]", buff_2[i]);
		}
		offset += 2;									// offset = 36
		short srcPort = DataUtils.byteArrayToShort(buff_2);
		tcp.setSrcPort(srcPort);

		String sourcePort = validateData(srcPort);
		protocolData.setSrcPort(sourcePort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		short dstPort = DataUtils.byteArrayToShort(buff_2);
		tcp.setDstPort(dstPort);

		String desPort = validateData(dstPort);
		protocolData.setDesPort(desPort);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 42
		int seqNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setSeqNum(seqNum);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 46
		int ackNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setAckNum(ackNum);

		byte headerLen = content[offset ++];			// offset = 47
		tcp.setHeaderLen(headerLen);

		byte flags = content[offset ++];				// offset = 48
		tcp.setFlags(flags);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 50
		short window = DataUtils.byteArrayToShort(buff_2);
		tcp.setWindow(window);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 52
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		tcp.setCheckSum(checkSum);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 54
		short urgentPointer = DataUtils.byteArrayToShort(buff_2);
		tcp.setUrgentPointer(urgentPointer);

//		LogUtils.printObj("tcp.offset", offset);
		data_offset = offset;
//		LogUtils.printObjInfo(tcp);

		return tcp;
	}

	private UDPHeader readUDPHeader(byte[] content, int offset) {
		byte[] buff_2 = new byte[2];

		UDPHeader udp = new UDPHeader();
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
//			LogUtils.printByteToBinaryStr("UDP: buff_2[" + i + "]", buff_2[i]);
		}
		offset += 2;									// offset = 36
		short srcPort = DataUtils.byteArrayToShort(buff_2);
		udp.setSrcPort(srcPort);

		String sourcePort = validateData(srcPort);
		protocolData.setSrcPort(sourcePort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		short dstPort = DataUtils.byteArrayToShort(buff_2);
		udp.setDstPort(dstPort);

		String desPort = validateData(dstPort);
		protocolData.setDesPort(desPort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 40
		short length = DataUtils.byteArrayToShort(buff_2);
		udp.setLength(length);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 42
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		udp.setCheckSum(checkSum);
		
//		LogUtils.printObj("udp.offset", offset );
//		LogUtils.printObjInfo(udp);
		data_offset = offset;

		return udp;
	}

	/**
	 * ��ȡ Pcap ����֡
	 * @param fis
	 */
	public void readPcapDataFrame(byte[] content) {
		PcapDataFrame dataFrame = new PcapDataFrame();
		int offset = 12;
		byte[] buff_2 = new byte[2];
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		short frameType = DataUtils.byteArrayToShort(buff_2);
		dataFrame.setFrameType(frameType);
		
//		LogUtils.printObjInfo(dataFrame);
	}

	private IPHeader readIPHeader(byte[] content) {
		int offset = 14;
		IPHeader ip = new IPHeader();

		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];

		byte varHLen = content[offset ++];				// offset = 15
//		LogUtils.printByteToBinaryStr("varHLen", varHLen);
		if (varHLen == 0) {
			return null;
		}
		
		ip.setVarHLen(varHLen);

		byte tos = content[offset ++];					// offset = 16
		ip.setTos(tos);

		for (int i = 0; i < 2; i ++) {		
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 18
		short totalLen = DataUtils.byteArrayToShort(buff_2);
		ip.setTotalLen(totalLen);

		for (int i = 0; i < 2; i ++) {			
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 20
		short id = DataUtils.byteArrayToShort(buff_2);
		ip.setId(id);

		for (int i = 0; i < 2; i ++) {					
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 22
		short flagSegment = DataUtils.byteArrayToShort(buff_2);
		ip.setFlagSegment(flagSegment);

		byte ttl = content[offset ++];					// offset = 23
		ip.setTtl(ttl);

		byte protocol = content[offset ++];				// offset = 24
		ip.setProtocol(protocol);

		for (int i = 0; i < 2; i ++) {					
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 26
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		ip.setCheckSum(checkSum);

		for (int i = 0; i < 4; i ++) {					
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 30
		int srcIP = DataUtils.byteArrayToInt(buff_4);
		ip.setSrcIP(srcIP);

		// ƴ�ӳ� SourceIP
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String sourceIP = builder.toString();
		protocolData.setSrcIP(sourceIP);

		for (int i = 0; i < 4; i ++) {		
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 34
		int dstIP = DataUtils.byteArrayToInt(buff_4);
		ip.setDstIP(dstIP);

		// ƴ�ӳ� DestinationIP
		builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String destinationIP = builder.toString();
		protocolData.setDesIP(destinationIP);

//		LogUtils.printObjInfo(ip);

		return ip;
	}

	/**
	 * �����ļ�
	 * @param protocolData
	 */
	public void createFiles(ProtocolData protocolData) {
		String protocol = "TCP";
		String suffix = ".pcap";
		if (protocolData.getProtocolType() == ProtocolType.UDP) {
			protocol = "UDP";
		}  else if (protocolData.getProtocolType() == ProtocolType.OTHER) {
			return;
		}
		String filename = protocol + "[" + protocolData.getSrcIP() + "]"
								   + "[" + protocolData.getSrcPort() + "]"
								   + "[" + protocolData.getDesIP() + "]"
								   + "[" + protocolData.getDesPort() + "]";
		
		String reverseFilename = protocol + "[" + protocolData.getDesIP() + "]"
								   		  + "[" + protocolData.getDesPort() + "]"
								   		  + "[" + protocolData.getSrcIP() + "]"
								   		  + "[" + protocolData.getSrcPort() + "]";
		boolean append = false;
		// �ж��Ƿ��Ѿ���������Ԫ��
		if (filenames.contains(filename)) {
			append = true;
//			LogUtils.printObj(filename + "�Ѵ���...");
		} else {
			append = false;
//			LogUtils.printObj(filename + "������...");
			
			// ��ԴIP��ԴPort��Ŀ��IP��Ŀ��Port ����˳�򣬲鿴���ļ��Ƿ���ڣ������ڣ���׷��
			if (filenames.contains(reverseFilename)) {
				append = true;
				filename = reverseFilename;
//				LogUtils.printObj("rf: " + reverseFilename + "�Ѵ���...");
			} else {
				filenames.add(filename);
			}
			
		}
		
		filename = DataUtils.validateFilename(filename);
		String pathname = savePath + "\\" + protocol + "\\" + filename + suffix;
		
		/*
		 * ���ݸ�����Ϣ
		 */
		int data_size = content.length - data_offset;
//		LogUtils.printObj("���ݸ��س�", data_size);
		data_content = new byte[data_size];
		for (int i = 0; i < data_size; i ++) {
			data_content[i] = content[i + data_offset];
		}
		String pathname_data = savePath + "\\" + protocol + "\\���ݸ�����ȡ���\\" + filename + ".txt";
		
		try {
			File file = new File(pathname);
			FileOutputStream fos = new FileOutputStream(file, append);
			
			File data_file = new File(pathname_data);
			FileOutputStream fos_data = new FileOutputStream(data_file, append);
			
			if (!append) {	// �� append Ϊ true�������ļ��Ѿ����ڣ�׷��
				// 1. д���ļ�ͷ
				fos.write(file_header);
				
				String[] data = new String[2];
				data[0] = filename;
				data[1] = pathname;
				datas.add(data);
				super.setChanged();								// ֪ͨ�۲���
				super.notifyObservers(datas);					// �������ݸ��۲���
				
				// �����ڣ���˵���ü�¼��δ���
				String logPath = savePath + "\\" + protocol + "\\" + protocol + ".txt";
				FileUtils.writeLineToFile(filename, new File(logPath), true);
			}
			
			// 2. д�� Pcap ����ͷ
//			LogUtils.printObj("data_header.length", data_header.length);
			fos.write(data_header);
			// 3. д������
//			LogUtils.printObj("content.length", content.length);
			fos.write(content);
			
			// д�����ݸ�����Ϣ
			fos_data.write(data_content);
			
			// 4. �ر���
			FileUtils.closeStream(null, fos);
			FileUtils.closeStream(null, fos_data);
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} 
		
	}

	/**
	 * �����˿ں�Ϊ��ֵ�ĵ���ת��Ϊʮ�������ݳ���
	 * @param data
	 * @return
	 */
	private String validateData (int data) {
		String rs = data + "";
		if (data < 0) {
			String binaryPort = Integer.toBinaryString(data);
			rs = DataUtils.binaryToDecimal(binaryPort) + "";
		}

		return rs;
	}
	
}
