package com.johnnie.pcapanalyzer.utils;

import java.awt.Dimension;
import java.awt.Toolkit;

/**
 * 窗体工具类
 * @author johnnie
 * @time 2015年12月13
 */
public class WindowUtils {

	private static final Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
	
	private WindowUtils () {}
	
	/**
	 * 获取用户电脑屏幕宽度
	 * @return
	 */
	public static int getScreenWidth () {
		return screenSize.width;
	}

	/**
	 * 获取用户电脑屏幕高度
	 * @return
	 */
	public static int getScreenHeight () {
		return screenSize.height;
	}
	
}
