
// ReadMachineCodeDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"


// CReadMachineCodeDlg �Ի���
class CReadMachineCodeDlg : public CDialogEx
{
// ����
public:
	CReadMachineCodeDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_READMACHINECODE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CEdit mEditCode;
	afx_msg void OnBnClickedButton1();
};