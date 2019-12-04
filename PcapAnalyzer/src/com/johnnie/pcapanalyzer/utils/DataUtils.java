package com.johnnie.pcapanalyzer.utils;

import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

/**
 * 数据工具类
 * @author johnnie
 *
 */
public class DataUtils {

	private DataUtils () {}

	/**
	 * 格式化十六进制数据
	 * @param hex
	 * @param type 2字节数据：0， 4 字节数据：1
	 * @return
	 */
	public static String formatHexData (String hex, int type) {
		int len = hex.length();		// 数据长

		if (type == 0) {			// 2 个字节的数据补 4 - len 个0
			if (len < 4) {			// 若小于 4，则前端补 0, 直到补齐 4 个数
				int correct = 4 - len;
				for (int i = 0; i < correct; i ++) {
					hex = "0" + hex;
				}
			}
		} else if (type == 1) {		// 4 字节数据补 8 - len 个0，并在中间补空格
			if (len <= 4) {			// 若小于等于 4
				int correct = 4 - len;
				for (int i = 0; i < correct; i ++) {
					hex = "0" + hex;// 前端补 0
				}

				hex += " 0000";		// 后端补空格与 0 
			} else if (len > 4) {	// 若是大于四，则在第4位和第五位数之间加上空格
				//				List<String> datas = Arrays.asList(hex.split(""));
				List<String> datas = new ArrayList<String>();
				for (String s : hex.split("")) {
					datas.add(s);
				}

				// 补满 9 位元素：否则后续的移位会出现数组越界错误
				int correct = 9 - len;
				for (int i = 0; i < correct; i ++) {
					datas.add(" ");
				}
				// 先移位，在插入数据
				for (int i = len; i > 3; i --) {	// 将元素后移
					datas.set(i, datas.get(i - 1));
				}
				// 元素插入
				datas.set(4, " ");
				StringBuilder builder = new StringBuilder();
				for (String s : datas) {
					builder.append(s);
				}
				hex = builder.toString();

				if (hex.length() < 9) {
					for (int i = 0; i < correct - 1; i ++) {
						hex += "0";
					}
				}
			}
		} else {					// 错误类型
			return null;
		}


		return null;
	}

	/**
	 * 将一维的字节数组逆序
	 * @param arr
	 */
	public static void reverseByteArray(byte[] arr){
		byte temp;
		int n = arr.length;
		for(int i = 0; i < n / 2; i++){
			temp = arr[i];
			arr[i] = arr[n - 1 - i];
			arr[n - 1 - i] = temp;
		}
	}

	/**
	 * byte 转 int
	 * @param b
	 * @return
	 */
	public static int byteToInt (byte b) {
		return (b & 0xff);
	}

	/**
	 * 一维字节数组转 int 值(4 字节)
	 * @param b
	 * @return
	 */
	public static int byteArrayToInt(byte[] b){
		return byteArrayToInt(b, 0);
	}

	/**
	 * 一维字节数组转 int 值(4 字节)
	 * @param b
	 * @param offset
	 * @return
	 */
	public static int byteArrayToInt(byte[] bytes, int offset){
		int value= 0;
		//由高位到低位
		for (int i = 0; i < 4; i++) {
			int shift= (4 - 1 - i) * 8;
			value +=(bytes[i] & 0x000000FF) << shift;//往高位游
		}

		return value;
	}

	/**
	 * 一维字节数组转 short 值(2 字节)
	 * @param b
	 * @return
	 */
	public static short byteArrayToShort(byte[] b){
		return byteArrayToShort(b, 0);
	}

	/**
	 * 一维字节数组转 short 值(2 字节)
	 * @param b
	 * @param offset
	 * @return
	 */
	public static short byteArrayToShort(byte[] b,int offset){
		return (short) (((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff)); 
	}

	/**
	 * byte 转为 16 进制字符串
	 * @param b
	 * @return
	 */
	public static String byteToHexString (byte b) {
		return intToHexString(byteToInt(b));
	}

	/**
	 * 将 int 类型数据转为 byte[] 
	 * @param data
	 * @return
	 */
	public static byte[] intToByteArray(int i) {
		byte[] result = new byte[4];   
		//由高位到低位
		result[0] = (byte)((i >> 24) & 0xFF);
		result[1] = (byte)((i >> 16) & 0xFF);
		result[2] = (byte)((i >> 8) & 0xFF); 
		result[3] = (byte)(i & 0xFF);
		return result;
	}

	/**
	 * short 转 16 进制字符串
	 * @param s
	 * @return
	 */
	public static String shortToHexString (short s) {
		String hex = intToHexString(s);
		int len = hex.length();
		if (len > 4) {	// 此时 short 值为负值，高位会补 1，变成 ffffed5c，因此截去符号位
			hex = hex.substring(4);
		} 

		len = hex.length();
		if (len < 4) {	// 若小于 4，则高位补 0
			int n = 4 - len;
			for (int i = 0; i < n; i ++) {
				hex = "0" + hex;
			}
		}

		return "0x" + hex;
	}

	/**
	 * 将 int 转为 16 进制字符串
	 * @param data
	 * @return
	 */
	public static String intToHexString (int data) {
		return Integer.toHexString(data);
	}

	/**
	 * 将二进制的数字字符串转为十进制
	 * @param str
	 */
	public static int binaryToDecimal (String str) {
		String[] strs = str.split("");
		List<Integer> datas = new ArrayList<Integer>();
		for (String s : strs) {
			datas.add(Integer.valueOf(s));
		}
		int size = datas.size();

		int values = 0;
		if (size <= 16) {
			for (int i = 0; i < size; i ++) {
				values += (datas.get(i) * ((int) Math.pow(2, size - i - 1)));
			}
		} else {	// 这种情况是该数值为负值，前面补 1
			// 只留下最后 16 位数
			int offset = size - 16;
			for (int i = 0; i < 16; i ++) {
				values += (datas.get(i + offset) * ((int) Math.pow(2, 16 - i - 1)));
			}
		}

		return values;
	}

	/**
	 * 将 byte 数组按顺序拼接为二进制数据 String
	 * @param b
	 * @return
	 */
	public static String byteArrayToBinaryString (byte[] bytes) {
		String line = "";
		for (byte b : bytes) {
			line += (Integer.toBinaryString(byteToInt(b)));
		}

		return line;
	}

	/**
	 * 将 long 数据处理成 KB 单位
	 * @return 字符串
	 */
	public static String toMBString (long i) {
		DecimalFormat format = new DecimalFormat("#.##");	// 取小数点后 2 位，向上取整
		return format.format((i / 1024.0));
	}

	/**
	 * 将 long 数据处理成 KB 单位(精确到小数点后2位, 向下取整)
	 * @return
	 */
	public static BigDecimal toMB (long i) {
		return roundDown(i / 1024.0);
	}

	/**
	 * 向下取整
	 * @param d
	 * @return
	 */
	public static BigDecimal roundDown (double d) {
		BigDecimal decimal = new BigDecimal((d));
		return scale(decimal, 2);
	}

	/**
	 * 设置向下取整及其精度
	 * @param decimal
	 * @param scale
	 * @return
	 */
	public static BigDecimal scale (BigDecimal decimal, int scale) {
		return decimal.setScale(scale, BigDecimal.ROUND_DOWN);
	}

	/**
	 * 校正文件名
	 * @param filename protocol五元组文件名 
	 * @return 符合格式的文件名(ip小的放在前面)
	 */
	public static String validateFilename (String filename) {
//		LogUtils.printObj("校正前", filename);
		
		String[] s1 = filename.split("\\[");	// TCP  59.175.132.20] 	80]   192.168.1.40]	1581]	
		String protocol = s1[0];
		String ip1 = s1[1].split("\\]")[0];
		String port1 = s1[2].split("\\]")[0];
		String ip2 = s1[3].split("\\]")[0];
		String port2 = s1[4].split("\\]")[0];

		// 切割 ip
		String[] ip_s1 = ip1.split("\\.");
		String[] ip_s2 = ip2.split("\\.");

		// 比较 ip 与 ip 的大小
		String rs = protocol + "[" + ip1 + "]"
				 			 + "[" + port1 + "]"
				 			 + "[" + ip2 + "]"
				 			 + "[" + port2 + "]";
		String tmp_ip = ip1;
		String tmp_port = port1;
		
		int ip1_part1 = Integer.valueOf(ip_s1[0]);
		int ip2_part1 = Integer.valueOf(ip_s2[0]);
		
		if (ip1_part1 > ip2_part1) {			// 若大于，则直接交换
			rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
		}  else if (ip1_part1 == ip2_part1) {	// 若等于, 则比较第二位
			
			int ip1_part2 = Integer.valueOf(ip_s1[1]);
			int ip2_part2 = Integer.valueOf(ip_s2[1]);
			if (ip1_part2 > ip2_part2) {
				rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
			} else if (ip1_part2 == ip2_part2) {	// 若等于, 则比较第三位
				
				int ip1_part3 = Integer.valueOf(ip_s1[2]);
				int ip2_part3 = Integer.valueOf(ip_s2[2]);
				if (ip1_part3 > ip2_part3) {
					rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
				} else if (ip1_part3 == ip2_part3) {	// 若小于等于, 则比较第四位
					
					int ip1_part4 = Integer.valueOf(ip_s1[3]);
					int ip2_part4 = Integer.valueOf(ip_s2[3]);
					if (ip1_part4 > ip2_part4) {
						rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
					} 
				}
			}
		} // 若小于，直接返回
		
//		LogUtils.printObj("校正后", rs);
//		LogUtils.printObj("\n");

		return rs;
	}
	
	/**
	 * 交换
	 * @param protocol
	 * @param ip2
	 * @param port2
	 * @param tmp_ip
	 * @param tmp_port
	 * @return
	 */
	private static String swape (String protocol, String ip2, String port2, String tmp_ip, String tmp_port) {
		String ip1 = ip2;
		ip2 = tmp_ip;

		String port1 = port2;
		port2 = tmp_port;
		String rs = protocol + "[" + ip1 + "]"
							 + "[" + port1 + "]"
							 + "[" + ip2 + "]"
							 + "[" + port2 + "]";
		
		return rs;
	}

}