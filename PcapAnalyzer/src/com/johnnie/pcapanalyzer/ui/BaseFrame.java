package com.johnnie.pcapanalyzer.ui;

import javax.swing.JFrame;

/**
 * 基类
 * @author johnnie
 * @time 2015年12月13
 */
public abstract class BaseFrame extends JFrame {

	private static final long serialVersionUID = 1L;

	private String title = "PcapAnalyzer";					// 窗体标题
	
	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}
	
	/**
	 * 初始化窗体组件
	 */
	public abstract void initViews();
	
	/**
	 * 监听各组件的事件
	 */
	public abstract void initEvents();
	
}
