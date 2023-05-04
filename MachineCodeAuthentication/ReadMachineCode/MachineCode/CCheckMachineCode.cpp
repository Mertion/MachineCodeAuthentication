#include "stdafx.h"
#include "CCheckMachineCode.h"

//��ȡCPUID����ͷ�ļ�
#include <iostream>
using namespace std;
#include <string>
#include <comutil.h>
#include "Windows.h"
#include <atlconv.h>
#include <intrin.h>
#include <cctype>
#include <iomanip>
#include "Encryption.h"

//��ȡ����MAC����ͷ�ļ���NetBios����--------��ʼ
#include <winsock2.h> //��ͷ�ļ�������Socket��̵Ĺ���
#include <stdio.h>    //��ͷ�ļ��������������������
#include <stdlib.h>   //��ͷ�ļ�������һЩͨ�ú���
#include <httpext.h>   //��ͷ�ļ�֧��HTTP����
#include <windef.h>   //��ͷ�ļ�������Windows���������ݻ�����̬
#include <Nb30.h>   //��ͷ�ļ�������netbios�����еĺ��� 
#pragma comment(lib, "ws2_32.lib")    //����ws2_32.lib��.ֻҪ�������õ�Winsock API ��������Ҫ�õ� Ws2_32.lib
#pragma comment(lib, "netapi32.lib")   //����Netapi32.lib�⣬MAC��ȡ���õ���NetApi32.DLL�Ĺ���
//��ȡ����MAC����ͷ�ļ���NetBios����--------����

//��ȡ����MAC����ͷ�ļ���SNMP����----------��ʼ
#include <snmp.h>
#include <conio.h>
#include <stdio.h>
typedef bool(WINAPI* pSnmpExtensionInit) (
	IN DWORD dwTimeZeroReference,
	OUT HANDLE* hPollForTrapEvent,
	OUT AsnObjectIdentifier* supportedView);

typedef bool(WINAPI* pSnmpExtensionTrap) (
	OUT AsnObjectIdentifier* enterprise,
	OUT AsnInteger* genericTrap,
	OUT AsnInteger* specificTrap,
	OUT AsnTimeticks* timeStamp,
	OUT RFC1157VarBindList* variableBindings);

typedef bool(WINAPI* pSnmpExtensionQuery) (
	IN BYTE requestType,
	IN OUT RFC1157VarBindList* variableBindings,
	OUT AsnInteger* errorStatus,
	OUT AsnInteger* errorIndex);

typedef bool(WINAPI* pSnmpExtensionInitEx) (
	OUT AsnObjectIdentifier* supportedView);

#pragma comment(lib, "Snmpapi.lib")
//��ȡ����MAC����ͷ�ļ���SNMP����----------����


CCheckMachineCode::CCheckMachineCode()
{
	//��ʼ���������ÿ����һ̨�豸��Ҫ�ڴ���Ӷ�Ӧ�Ļ����롣
	mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000A06528C8CAA961664"), 0));
	//mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000A06528C8CAA961664"), 0));
	//Win7 �����
	mlistMachineCode.insert(pair<CString, int>(CString("1F8BFBFF000A0652000C295EE192"), 0));
	//�г̵���ӡ PC1
	mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000906EA000C291DBFD6"), 0));
	//�г̵���ӡ PC2
	mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000306C3000C291DBFD6"), 0));
	
}

CCheckMachineCode::~CCheckMachineCode()
{
}

//���ɻ�����
int CCheckMachineCode::BuildMachineCode(CString& p_strMachineCode)
{
	char chrCpuId[32] = "";
	map<CString, int> listMac;
	

	if (GetCPUID(chrCpuId) != 0)
	{
		return 1;
	}
	
	if (GetMacList(listMac))
	{
		return 2;
	}

	map <CString, int>::iterator m1_Iter;
	m1_Iter = listMac.begin();
	if (m1_Iter != listMac.end())
	{
		CString strMac = m1_Iter->first;

		//����ʱ��������������࣬Ȼ��3des���ܣ���󽫼��ܽ�����
		SYSTEMTIME sys;
		GetLocalTime(&sys);
		CString strTime;
		//printf("%4d/%02d/%02d %02d:%02d:%02d.%03d ����%1d\n", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds, sys.wDayOfWeek);
		strTime.Format(_T(" %03d"), sys.wMilliseconds);
		CString strMachineCode = CString(chrCpuId) + strTime + strMac;

		string strCode = CStringA(strMachineCode).GetBuffer();
		string strKey = "szsucc.com szsuc";
		string strKeyHex = "";
		char pDestData[1024] = { 0 };
		
		StrToAsciiHexStr(strKey, strKeyHex);
		const char* pchrKey = strKeyHex.c_str();
		const char* pchrCode = strCode.c_str();
		TriDESECB(1, (UCHAR*)pchrKey, 0, (UCHAR*)pchrCode, (UCHAR* )pDestData);

		
		p_strMachineCode = pDestData;
	}
	else
	{
		return 3;
	}

	return 0;
}

//����������
int CCheckMachineCode::AnalysisMachineCode(CString p_strMachineCode)
{
	//���Խ��ܲ���
	char pDecData[1024] = { 0 };
	string strKey = "szsucc.com szsuc";
	string strKeyHex = "";
	StrToAsciiHexStr(strKey, strKeyHex);
	const char* pchrKey = strKeyHex.c_str();
	string strCode = CStringA(p_strMachineCode);
	const char* pDestData = strCode.c_str();
	TriDESECB(0, (UCHAR*)pchrKey, 1, (UCHAR*)pDestData, (UCHAR*)pDecData);
	//���ܺ�������Ҫ��AsciiHex���ַ��Ļ���,����Ҫע���β���������
	string strDec = pDecData;
	string strMCode;
	AsciiHexStrToStr(strDec, strMCode);

	string strMachineCode;
	strMachineCode = strMCode.substr(0, 16);
	strMachineCode += strMCode.substr(20);
	return 0;
}

int CCheckMachineCode::CheckMachineCode()
{	
	char chrCpuId[32] = "";
	map<CString, int> listMac;

	if (GetCPUID(chrCpuId) != 0)
	{
		return 1;
	}

	if (GetMacList(listMac))
	{
		return 2;
	}

	map <CString, int>::iterator m1_Iter;
	map <CString, int>::iterator itcFind;
	for (m1_Iter = listMac.begin(); m1_Iter != listMac.end(); m1_Iter++)
	{
		CString strMac = m1_Iter->first;
		CString strMachineCode = CString(chrCpuId) + strMac;

		itcFind = mlistMachineCode.find(strMachineCode);
		if (itcFind!= mlistMachineCode.end())
		{
			return 0;
		}
	}

	return 3;
}

int CCheckMachineCode::GetCPUID(char* p_pcharCPUID /*= nullptr*/)
{
	char pCpuId[32] = "";

	int dwBuf[4];
	getcpuid((unsigned int*)dwBuf, 1);
	sprintf_s(pCpuId, 32, "%08X", dwBuf[3]);
	sprintf_s(pCpuId + 8, 24, "%08X", dwBuf[0]);

	if (p_pcharCPUID != nullptr)
	{
		memcpy(p_pcharCPUID, pCpuId, 32);
	}
	else
	{
		return 1;
	}

	return 0;
}

void CCheckMachineCode::getcpuid(unsigned int* CPUInfo, unsigned int InfoType)
{
#if defined(__GNUC__)// GCC  
	__cpuid(InfoType, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
#elif defined(_MSC_VER)// MSVC  
#if _MSC_VER >= 1400 //VC2005��֧��__cpuid  
	__cpuid((int*)(void*)CPUInfo, (int)(InfoType));
#else //����ʹ��getcpuidex  
	getcpuidex(CPUInfo, InfoType, 0);
#endif  
#endif  
}

void CCheckMachineCode::getcpuidex(unsigned int* CPUInfo, unsigned int InfoType, unsigned int ECXValue)
{
#if defined(_MSC_VER) // MSVC  
#if defined(_WIN64) // 64λ�²�֧���������. 1600: VS2010, ��˵VC2008 SP1֮���֧��__cpuidex.  
	__cpuidex((int*)(void*)CPUInfo, (int)InfoType, (int)ECXValue);
#else  
	if (NULL == CPUInfo)
		return;
	_asm {
		// load. ��ȡ�������Ĵ���.  
		mov edi, CPUInfo;
		mov eax, InfoType;
		mov ecx, ECXValue;
		// CPUID  
		cpuid;
		// save. ���Ĵ������浽CPUInfo  
		mov[edi], eax;
		mov[edi + 4], ebx;
		mov[edi + 8], ecx;
		mov[edi + 12], edx;
	}
#endif  
#endif  
}

//��ȡ����Mac�б�Netbios�������÷���ֻ�ܻ�ȡ�����ӵ�������ַ������������
int CCheckMachineCode::GetMac(int & p_pnNetNumber,char** p_pchrNetMac)
{
	int nRet = 0;
	NCB ncb;
	NCB ncbMac;

	typedef struct _ASTAT_     
	{
		ADAPTER_STATUS   adapt;
		NAME_BUFFER   NameBuff[30];
	}ASTAT, * PASTAT;
	ASTAT Adapter;

	typedef struct _LANA_ENUM     
	{
		UCHAR length;
		UCHAR lana[MAX_LANA];     //�������MAC��ַ 
	}LANA_ENUM;
	LANA_ENUM lana_enum;

	//   ȡ��������Ϣ�б�     
	UCHAR uRetCode;
	memset(&ncb, 0, sizeof(ncb));		
	memset(&lana_enum, 0, sizeof(lana_enum));    
	//ͳ��ϵͳ������������
	ncb.ncb_command = NCBENUM;						
	ncb.ncb_buffer = (unsigned char*)&lana_enum;
	ncb.ncb_length = sizeof(LANA_ENUM);
	//����������NCBENUM����Ի�ȡ��ǰ������������Ϣ�����ж��ٸ����� 
	uRetCode = Netbios(&ncb);   
	if (uRetCode != NRC_GOODRET)
	{
		AfxMessageBox(_T("Failed to obtain the number of network cards!"));

		nRet = 1;
	}
	else
	{
		if (lana_enum.length > 0)
		{
			p_pchrNetMac = new char* [lana_enum.length];
			for (int i = 0; i < lana_enum.length; i++)
			{
				p_pchrNetMac[i] = new char[32];
				memset(p_pchrNetMac[i], 0, 32);
			}
		}

		//��ÿһ�������������������Ϊ�����ţ���ȡ��MAC��ַ   
		for (int lana = 0; lana < lana_enum.length; lana++)
		{
			//����������NCBRESET������г�ʼ��
			ncb.ncb_command = NCBRESET;
			ncb.ncb_lana_num = lana_enum.lana[lana];
			uRetCode = Netbios(&ncb);
			if (uRetCode != NRC_GOODRET)
			{
				AfxMessageBox(_T("Network card initialization failed!"));
				nRet = 1;
				break;
			}

			//��ȡ����mac
			memset(&ncbMac, 0, sizeof(ncbMac));
			//����������NCBSTAT�����ȡ������Ϣ
			ncbMac.ncb_command = NCBASTAT;
			//ָ��������	
			ncbMac.ncb_lana_num = lana_enum.lana[lana];
			//#pragma warning(disable:4996)
			//		strcpy((char*)ncbMac.ncb_callname, "*");
			//#pragma warning(default: 4996)
			//Զ��ϵͳ����ֵΪ*
			ncbMac.ncb_callname[0] = '*';
			ncbMac.ncb_buffer = (unsigned char*)&Adapter;
			ncbMac.ncb_length = sizeof(Adapter);
			//���ŷ���NCBASTAT�����Ի�ȡ��������Ϣ
			uRetCode = Netbios(&ncbMac);
			if (uRetCode != NRC_GOODRET)
			{
				AfxMessageBox(_T("Failed to read mac!"));
				nRet = 1;
				break;
			}
			
			sprintf_s(p_pchrNetMac[lana], 32, "%02X-%02X-%02X-%02X-%02X-%02X",
				Adapter.adapt.adapter_address[0],
				Adapter.adapt.adapter_address[1],
				Adapter.adapt.adapter_address[2],
				Adapter.adapt.adapter_address[3],
				Adapter.adapt.adapter_address[4],
				Adapter.adapt.adapter_address[5]);
		}

	}
	
	return nRet;
}

//��ȡ����Mac�б�ʹ��SNMP����������֤�÷������Ի������������Ϣ������Ҫ�����ظ�����
int CCheckMachineCode::GetMacList(map<CString, int>& p_plistMac)
{
	HINSTANCE m_hInst;
	pSnmpExtensionInit m_Init;
	pSnmpExtensionInitEx m_InitEx;
	pSnmpExtensionQuery m_Query;
	pSnmpExtensionTrap m_Trap;
	HANDLE PollForTrapEvent;
	AsnObjectIdentifier SupportedView;
	UINT OID_ifEntryType[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 3 };
	UINT OID_ifEntryNum[] = { 1, 3, 6, 1, 2, 1, 2, 1 };
	UINT OID_ipMACEntAddr[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 6 };
	AsnObjectIdentifier MIB_ifMACEntAddr = { sizeof(OID_ipMACEntAddr) / sizeof(UINT), OID_ipMACEntAddr };
	AsnObjectIdentifier MIB_ifEntryType = { sizeof(OID_ifEntryType) / sizeof(UINT), OID_ifEntryType };
	AsnObjectIdentifier MIB_ifEntryNum = { sizeof(OID_ifEntryNum) / sizeof(UINT), OID_ifEntryNum };
	RFC1157VarBindList varBindList;
	RFC1157VarBind varBind[2];
	AsnInteger errorStatus;
	AsnInteger errorIndex;
	AsnObjectIdentifier MIB_NULL = { 0, 0 };
	int ret;
	int dtmp;
	int i = 0, j = 0;
	bool found = false;

	m_Init = NULL;
	m_InitEx = NULL;
	m_Query = NULL;
	m_Trap = NULL;

	/* ����SNMP DLL��ȡ��ʵ����� */
	m_hInst = LoadLibrary(_T("inetmib1.dll"));
	if (m_hInst < (HINSTANCE)HINSTANCE_ERROR)
	{
		m_hInst = NULL;
		return 1;
	}
	m_Init = (pSnmpExtensionInit)GetProcAddress(m_hInst, "SnmpExtensionInit");
	m_InitEx = (pSnmpExtensionInitEx)GetProcAddress(m_hInst, "SnmpExtensionInitEx");
	m_Query = (pSnmpExtensionQuery)GetProcAddress(m_hInst, "SnmpExtensionQuery");
	m_Trap = (pSnmpExtensionTrap)GetProcAddress(m_hInst, "SnmpExtensionTrap");

	m_Init(GetTickCount(), &PollForTrapEvent, &SupportedView);

	/* ��ʼ����������m_Query��ѯ����ı����б� */
	varBindList.list = varBind;
	varBind[0].name = MIB_NULL;
	varBind[1].name = MIB_NULL;

	/* ��OID�п��������ҽӿڱ��е�������� */
	varBindList.len = 1;        /* Only retrieving one item */
	SNMP_oidcpy(&varBind[0].name, &MIB_ifEntryNum);
	ret = m_Query(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex);
	//printf("# of adapters in this system : %in",varBind[0].value.asnValue.number);
	varBindList.len = 2;

	/* ����OID��ifType���ӿ����� */
	SNMP_oidcpy(&varBind[0].name, &MIB_ifEntryType);

	/* ����OID��ifPhysAddress�������ַ */
	SNMP_oidcpy(&varBind[1].name, &MIB_ifMACEntAddr);

	do
	{
		/* �ύ��ѯ����������� varBindList��
		����Ԥ�����ѭ�����õĴ�����ϵͳ�еĽӿڿ�������� */
		ret = m_Query(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex);
		if (!ret)
		{
			ret = 1;
		}
		else
		{
			/* ȷ����ȷ�ķ������� */
			ret = SNMP_oidncmp(&varBind[0].name, &MIB_ifEntryType, MIB_ifEntryType.idLength);
			if (!ret)
			{

				dtmp = varBind[0].value.asnValue.number;
				//printf("Interface #%i type : %in", j, dtmp);

				/* Type 6 describes ethernet interfaces */
				if (dtmp == 6)
				{
					/* ȷ�������Ѿ��ڴ�ȡ�õ�ַ */
					ret = SNMP_oidncmp(&varBind[1].name, &MIB_ifMACEntAddr, MIB_ifMACEntAddr.idLength);
					if ((!ret) && (varBind[1].value.asnValue.address.stream != NULL))
					{
						if ((varBind[1].value.asnValue.address.stream[0] == 0x44) && (varBind[1].value.asnValue.address.stream[1] == 0x45)
							&& (varBind[1].value.asnValue.address.stream[2] == 0x53) && (varBind[1].value.asnValue.address.stream[3] == 0x54)
							&& (varBind[1].value.asnValue.address.stream[4] == 0x00))
						{
							/* �������еĲ�������ӿڿ� */
							//printf("Interface #%i is a DUN adaptern", j);
							continue;
						}

						if ((varBind[1].value.asnValue.address.stream[0] == 0x00)
							&& (varBind[1].value.asnValue.address.stream[1] == 0x00)
							&& (varBind[1].value.asnValue.address.stream[2] == 0x00)
							&& (varBind[1].value.asnValue.address.stream[3] == 0x00)
							&& (varBind[1].value.asnValue.address.stream[4] == 0x00)
							&& (varBind[1].value.asnValue.address.stream[5] == 0x00))
						{
							/* ����������������ӿڿ����ص�NULL��ַ */
							//printf("Interface #%i is a NULL addressn", j);
							continue;
						}

						CString strMac;
						strMac.Format(_T("%02X%02X%02X%02X%02X%02X"),
							varBind[1].value.asnValue.address.stream[0],
							varBind[1].value.asnValue.address.stream[1],
							varBind[1].value.asnValue.address.stream[2],
							varBind[1].value.asnValue.address.stream[3],
							varBind[1].value.asnValue.address.stream[4],
							varBind[1].value.asnValue.address.stream[5]);

						p_plistMac.insert(pair<CString, int>(strMac, j));
						j++;
					}
				}
			}
		}
	} while (!ret);         /* ����������ֹ�� */


	FreeLibrary(m_hInst);
	/* ����� */
	SNMP_FreeVarBind(&varBind[0]);
	SNMP_FreeVarBind(&varBind[1]);

	return 0;
}