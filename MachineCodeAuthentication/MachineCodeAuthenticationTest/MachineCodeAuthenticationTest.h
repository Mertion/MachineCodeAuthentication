
// MachineCodeAuthenticationTest.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMachineCodeAuthenticationTestApp: 
// �йش����ʵ�֣������ MachineCodeAuthenticationTest.cpp
//

class CMachineCodeAuthenticationTestApp : public CWinApp
{
public:
	CMachineCodeAuthenticationTestApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CMachineCodeAuthenticationTestApp theApp;