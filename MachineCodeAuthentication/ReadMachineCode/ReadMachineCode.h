
// ReadMachineCode.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CReadMachineCodeApp: 
// �йش����ʵ�֣������ ReadMachineCode.cpp
//

class CReadMachineCodeApp : public CWinApp
{
public:
	CReadMachineCodeApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CReadMachineCodeApp theApp;