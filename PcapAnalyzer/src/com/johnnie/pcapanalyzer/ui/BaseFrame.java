package com.johnnie.pcapanalyzer.ui;

import javax.swing.JFrame;

/**
 * ����
 * @author johnnie
 * @time 2015��12��13
 */
public abstract class BaseFrame extends JFrame {

	private static final long serialVersionUID = 1L;

	private String title = "PcapAnalyzer";					// �������
	
	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}
	
	/**
	 * ��ʼ���������
	 */
	public abstract void initViews();
	
	/**
	 * ������������¼�
	 */
	public abstract void initEvents();
	
}
