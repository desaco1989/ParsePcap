package com.johnnie.pcapanalyzer.utils;

import java.util.List;

public class LogUtils {
	
	private LogUtils () {}
	
	/**
	 * ����״̬
	 */
	public static final int DEBUG = 0;
	
	/**
	 * ����״̬
	 */
	public static final int DEVELOPMENT = 1;
	
	/**
	 * ��Ҫ��Ϣ����Ϊ�ü�������Դ�ӡ��Ҫ��Ϣ(��ϵͳ��ʱ)�����˵��Ǳ�Ҫ��Ϣ
	 */
	public static final int SYSTEM = 3;
	
	/**
	 * ���Ƴ����Ƿ������Ϣ������̨
	 */
	public static final int CURRENT = DEBUG;
	
	/**
	 * ��ӡ����� Info ��Ϣ
	 * @param obj
	 */
	public static void printObjInfo (Object obj){
		printObjInfo(null, obj);
	}
	
	/**
	 * ��ӡ����� Info ��Ϣ
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
	 * �� byte תΪ�����Ʊ�ʾ
	 * @param suffix ����ǰ׺�ַ���
	 * @param b
	 */
	public static void printByteToBinaryStr (String prefix, byte b) {
		if (CURRENT < DEVELOPMENT) {
			System.out.println(prefix + ":::" + b + "�Ķ�����Ϊ" + Integer.toBinaryString(DataUtils.byteToInt(b)));
		}
	}
	
	/**
	 * ��ӡ������Ϣ
	 * @param obj
	 */
	public static void printObj (Object obj) {
		printObj(null, obj);
	}
	
	/**
	 * ��ӡ������Ϣ
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
	 * ��ӡһά�ֽ�����
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
	 * ��ʱ���
	 * @param time
	 */
	public static void printTimeCost (String prefix, long time) {
		if (CURRENT == SYSTEM) {
			if (TextUtils.isEmpty(prefix)) {
				System.out.println("��ʱ��" + time + "ms");
			} else {
				System.out.println(prefix + " : " + time + "ms");
			}
		}
	}
	
	/**
	 * ��ӡ List<String[]>
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
	 * ��ӡ�ַ�������
	 */
	public static void printStrArr (String[] arr) {
		for (String s : arr) {
			printObj(s);
		}
		printObj("\n");
	}
	
}
