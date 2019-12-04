package com.johnnie.pcapanalyzer.utils;

/**
 * 常量类
 * @author johnnie
 *
 */
public class Constant {

	private Constant () {}
	
	
	
//	public static final String LOG_RECENT_FILE = "sources\\log\\recentFile.properties";
	public static final String LOG_DIR = "C:\\PcapAnalyzer\\";
	public static final String LOG_RECENT_FILE = LOG_DIR + "recentFile.properties";
	public static final String ABOUT = "本软件的功能如下：\n"
										  + "1. 从 Pcap 文件提取 TCP 和 UDP 会话包\n"
										  + "2. 从提取出来的 TCP 和 UDP 包中恢复数据\n"
										  + "\n本软件仅供学习交流，不能商用\n"
										  + "版权所有：华中科技大学研一1504班焦鹏\n";
}
