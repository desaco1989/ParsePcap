package com.johnnie.pcapanalyzer.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

public class PropertiesUtils {

	/**
	 * 追加数据到  properties 文件中
	 * @param pathname
	 * @param key
	 * @param value
	 * @param apend
	 */
	public static void write (String pathname, String key, String value) {
		write(pathname, key, value, true);
	}
	
	/**
	 * 写入数据到  properties 文件中
	 * @param pathname
	 * @param key
	 * @param value
	 * @param apend   是否追加写入
	 */
	public static void write (String pathname, String key, String value, boolean apend) {
		Properties properties = new Properties();
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(new File(pathname), apend);
			properties.setProperty(key, value);
			properties.store(fos, null);
			FileUtils.closeStream(null, fos);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 从 properties 文件中读取数据
	 * @param pathname
	 * @param key
	 * @return
	 */
	public static String read (String pathname, String key) {
		String value = null;
		Properties properties = new Properties();
		FileInputStream fis = getInStream(pathname);
		try {
			properties.load(fis);
			value = properties.getProperty(key);
			FileUtils.closeStream(fis, null);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return value;
	}
	
	/**
	 * 判断 properties 文件中是否存在某一值
	 * @param pathname
	 * @param key
	 * @return
	 */
	public static boolean contains (String pathname, String key) {
		boolean rs = false;
		Properties properties = new Properties();
		FileInputStream fis = getInStream(pathname);
		try {
			properties.load(fis);
			
			if (properties.containsKey(key)) {
				rs = true;
			}
			
			FileUtils.closeStream(fis, null);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return rs;
	}
	
	/**
	 * 判断文件内容是否为空
	 * @param pathname
	 * @return
	 */
	public static boolean isEmpty (String pathname) {
		boolean isEmp = false;
		Properties properties = new Properties();
		FileInputStream fis = getInStream(pathname);
		try {
			properties.load(fis);
			if (properties.isEmpty()) {
				isEmp = true;
			} 
			FileUtils.closeStream(fis, null);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return isEmp;
	}
	
	/**
	 * 获取所有值
	 * @param pathname
	 * @return
	 */
	public static Object[] getVals (String pathname) {
		Object[] values = null;
		Properties properties = new Properties();
		FileInputStream fis = getInStream(pathname);
		try {
			properties.load(fis);
			values = properties.values().toArray();
			FileUtils.closeStream(fis, null);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return values;
	}
	

	/**
	 * 得到输入流
	 * @param pathname
	 * @return
	 */
	private static FileInputStream getInStream(String pathname) {
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(new File(pathname));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		return fis;
	}
	
	/**
	 * 清空数据
	 * @param pathname
	 */
	public static void clear (String pathname) {
		FileUtils.createEmpFile(pathname);
	}
	

}
