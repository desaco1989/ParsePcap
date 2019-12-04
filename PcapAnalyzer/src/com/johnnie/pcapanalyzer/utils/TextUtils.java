package com.johnnie.pcapanalyzer.utils;

public class TextUtils {
	
	private TextUtils () {}
	
	/**
	 * ÅÐ¶Ï×Ö·û´®ÊÇ·ñÎª¿Õ
	 * @param str
	 * @return
	 */
	public static boolean isEmpty (String str) {
		if (str == null || str.length() < 0) {
			return true;
		} else {
			return false;
		}
	}
	
}
