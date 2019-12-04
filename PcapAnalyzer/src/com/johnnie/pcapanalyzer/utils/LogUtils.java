package com.johnnie.pcapanalyzer.utils;

import java.util.List;

public class LogUtils {
	
	private LogUtils () {}
	
	/**
	 * 调试状态
	 */
	public static final int DEBUG = 0;
	
	/**
	 * 发布状态
	 */
	public static final int DEVELOPMENT = 1;
	
	/**
	 * 重要信息：若为该级别，则可以打印重要信息(如系统耗时)，过滤掉非必要信息
	 */
	public static final int SYSTEM = 3;
	
	/**
	 * 控制程序是否输出信息到控制台
	 */
	public static final int CURRENT = DEBUG;
	
	/**
	 * 打印对象的 Info 信息
	 * @param obj
	 */
	public static void printObjInfo (Object obj){
		printObjInfo(null, obj);
	}
	
	/**
	 * 打印对象的 Info 信息
	 * @param TAG
	 * @param obj
	 */
	public static void printObjInfo (final String TAG, Object obj){
		if (CURRENT < DEVELOPMENT) {
			if (TextUtils.isEmpty(TAG)) {
				System.out.println(obj.toString());
			} else {
				System.out.println(TAG + ", " + obj.toString());
			}
		}
	}
	
	/**
	 * 将 byte 转为二进制表示
	 * @param suffix 附加前缀字符串
	 * @param b
	 */
	public static void printByteToBinaryStr (String prefix, byte b) {
		if (CURRENT < DEVELOPMENT) {
			System.out.println(prefix + ":::" + b + "的二进制为" + Integer.toBinaryString(DataUtils.byteToInt(b)));
		}
	}
	
	/**
	 * 打印对象信息
	 * @param obj
	 */
	public static void printObj (Object obj) {
		printObj(null, obj);
	}
	
	/**
	 * 打印对象信息
	 * @param suffix
	 * @param obj
	 */
	public static void printObj (String prefix, Object obj) {
		if (CURRENT < DEVELOPMENT) {
			if (!TextUtils.isEmpty(prefix)) {
				System.out.println(prefix + " : " + obj);
			} else {
				System.out.println(obj);
			}
			
		}
	}
	
	/**
	 * 打印一维字节数组
	 * @param arr
	 */
	public static void printByteArray (byte[] arr) {
		if (CURRENT < DEVELOPMENT) {
			for (int i = 0; i < arr.length; i ++) {
				System.out.print(arr[i] + " " );
			}
			System.out.println();
		}
	}
	
	/**
	 * 耗时输出
	 * @param time
	 */
	public static void printTimeCost (String prefix, long time) {
		if (CURRENT == SYSTEM) {
			if (TextUtils.isEmpty(prefix)) {
				System.out.println("耗时：" + time + "ms");
			} else {
				System.out.println(prefix + " : " + time + "ms");
			}
		}
	}
	
	/**
	 * 打印 List<String[]>
	 * @param datas
	 */
	public static void printList (List<String[]> datas) {
		for (String[] s : datas) {
			printObj("filename", s[0]);
			printObj("pathname", s[1]);
			printObj("");
		}
	}
	
	/**
	 * 打印字符串数组
	 */
	public static void printStrArr (String[] arr) {
		for (String s : arr) {
			printObj(s);
		}
		printObj("\n");
	}
	
}
