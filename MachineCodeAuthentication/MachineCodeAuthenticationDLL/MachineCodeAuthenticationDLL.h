// MachineCodeAuthenticationDLL.h : MachineCodeAuthenticationDLL DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMachineCodeAuthenticationDLLApp
// �йش���ʵ�ֵ���Ϣ������� MachineCodeAuthenticationDLL.cpp
//

class CMachineCodeAuthenticationDLLApp : public CWinApp
{
public:
	CMachineCodeAuthenticationDLLApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};
