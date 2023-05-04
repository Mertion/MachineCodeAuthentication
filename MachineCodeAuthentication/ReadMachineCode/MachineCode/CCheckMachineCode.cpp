#include "stdafx.h"
#include "CCheckMachineCode.h"

//读取CPUID所需头文件
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

//读取网卡MAC所需头文件，NetBios方法--------开始
#include <winsock2.h> //该头文件定义了Socket编程的功能
#include <stdio.h>    //该头文件声明了输入输出流函数
#include <stdlib.h>   //该头文件定义了一些通用函数
#include <httpext.h>   //该头文件支持HTTP请求
#include <windef.h>   //该头文件定义了Windows的所有数据基本型态
#include <Nb30.h>   //该头文件声明了netbios的所有的函数 
#pragma comment(lib, "ws2_32.lib")    //连接ws2_32.lib库.只要程序中用到Winsock API 函数，都要用到 Ws2_32.lib
#pragma comment(lib, "netapi32.lib")   //连接Netapi32.lib库，MAC获取中用到了NetApi32.DLL的功能
//读取网卡MAC所需头文件，NetBios方法--------结束

//读取网卡MAC所需头文件，SNMP方法----------开始
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
//读取网卡MAC所需头文件，SNMP方法----------结束


CCheckMachineCode::CCheckMachineCode()
{
	//初始化机器码表，每新增一台设备都要在此添加对应的机器码。
	mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000A06528C8CAA961664"), 0));
	//mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000A06528C8CAA961664"), 0));
	//Win7 虚拟机
	mlistMachineCode.insert(pair<CString, int>(CString("1F8BFBFF000A0652000C295EE192"), 0));
	//行程单打印 PC1
	mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000906EA000C291DBFD6"), 0));
	//行程单打印 PC2
	mlistMachineCode.insert(pair<CString, int>(CString("BFEBFBFF000306C3000C291DBFD6"), 0));
	
}

CCheckMachineCode::~CCheckMachineCode()
{
}

//生成机器码
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

		//增加时间因子与机器码混编，然后3des加密，最后将加密结果输出
		SYSTEMTIME sys;
		GetLocalTime(&sys);
		CString strTime;
		//printf("%4d/%02d/%02d %02d:%02d:%02d.%03d 星期%1d\n", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds, sys.wDayOfWeek);
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

//解析机器码
int CCheckMachineCode::AnalysisMachineCode(CString p_strMachineCode)
{
	//测试解密部分
	char pDecData[1024] = { 0 };
	string strKey = "szsucc.com szsuc";
	string strKeyHex = "";
	StrToAsciiHexStr(strKey, strKeyHex);
	const char* pchrKey = strKeyHex.c_str();
	string strCode = CStringA(p_strMachineCode);
	const char* pDestData = strCode.c_str();
	TriDESECB(0, (UCHAR*)pchrKey, 1, (UCHAR*)pDestData, (UCHAR*)pDecData);
	//解密后数据需要做AsciiHex到字符的换算,并且要注意结尾补零的问题
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
#if _MSC_VER >= 1400 //VC2005才支持__cpuid  
	__cpuid((int*)(void*)CPUInfo, (int)(InfoType));
#else //其他使用getcpuidex  
	getcpuidex(CPUInfo, InfoType, 0);
#endif  
#endif  
}

void CCheckMachineCode::getcpuidex(unsigned int* CPUInfo, unsigned int InfoType, unsigned int ECXValue)
{
#if defined(_MSC_VER) // MSVC  
#if defined(_WIN64) // 64位下不支持内联汇编. 1600: VS2010, 据说VC2008 SP1之后才支持__cpuidex.  
	__cpuidex((int*)(void*)CPUInfo, (int)InfoType, (int)ECXValue);
#else  
	if (NULL == CPUInfo)
		return;
	_asm {
		// load. 读取参数到寄存器.  
		mov edi, CPUInfo;
		mov eax, InfoType;
		mov ecx, ECXValue;
		// CPUID  
		cpuid;
		// save. 将寄存器保存到CPUInfo  
		mov[edi], eax;
		mov[edi + 4], ebx;
		mov[edi + 8], ecx;
		mov[edi + 12], edx;
	}
#endif  
#endif  
}

//获取网卡Mac列表，Netbios方法，该方法只能获取已连接的网卡地址，不满足需求
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
		UCHAR lana[MAX_LANA];     //存放网卡MAC地址 
	}LANA_ENUM;
	LANA_ENUM lana_enum;

	//   取得网卡信息列表     
	UCHAR uRetCode;
	memset(&ncb, 0, sizeof(ncb));		
	memset(&lana_enum, 0, sizeof(lana_enum));    
	//统计系统中网卡的数量
	ncb.ncb_command = NCBENUM;						
	ncb.ncb_buffer = (unsigned char*)&lana_enum;
	ncb.ncb_length = sizeof(LANA_ENUM);
	//向网卡发送NCBENUM命令，以获取当前机器的网卡信息，如有多少个网卡 
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

		//对每一个网卡，以其网卡编号为输入编号，获取其MAC地址   
		for (int lana = 0; lana < lana_enum.length; lana++)
		{
			//对网卡发送NCBRESET命令，进行初始化
			ncb.ncb_command = NCBRESET;
			ncb.ncb_lana_num = lana_enum.lana[lana];
			uRetCode = Netbios(&ncb);
			if (uRetCode != NRC_GOODRET)
			{
				AfxMessageBox(_T("Network card initialization failed!"));
				nRet = 1;
				break;
			}

			//读取网卡mac
			memset(&ncbMac, 0, sizeof(ncbMac));
			//对网卡发送NCBSTAT命令，获取网卡信息
			ncbMac.ncb_command = NCBASTAT;
			//指定网卡号	
			ncbMac.ncb_lana_num = lana_enum.lana[lana];
			//#pragma warning(disable:4996)
			//		strcpy((char*)ncbMac.ncb_callname, "*");
			//#pragma warning(default: 4996)
			//远程系统名赋值为*
			ncbMac.ncb_callname[0] = '*';
			ncbMac.ncb_buffer = (unsigned char*)&Adapter;
			ncbMac.ncb_length = sizeof(Adapter);
			//接着发送NCBASTAT命令以获取网卡的信息
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

//获取网卡Mac列表，使用SNMP方法，经验证该方法可以获得所有网卡信息，但需要过滤重复数据
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

	/* 载入SNMP DLL并取得实例句柄 */
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

	/* 初始化用来接收m_Query查询结果的变量列表 */
	varBindList.list = varBind;
	varBind[0].name = MIB_NULL;
	varBind[1].name = MIB_NULL;

	/* 在OID中拷贝并查找接口表中的入口数量 */
	varBindList.len = 1;        /* Only retrieving one item */
	SNMP_oidcpy(&varBind[0].name, &MIB_ifEntryNum);
	ret = m_Query(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex);
	//printf("# of adapters in this system : %in",varBind[0].value.asnValue.number);
	varBindList.len = 2;

	/* 拷贝OID的ifType－接口类型 */
	SNMP_oidcpy(&varBind[0].name, &MIB_ifEntryType);

	/* 拷贝OID的ifPhysAddress－物理地址 */
	SNMP_oidcpy(&varBind[1].name, &MIB_ifMACEntAddr);

	do
	{
		/* 提交查询，结果将载入 varBindList。
		可以预料这个循环调用的次数和系统中的接口卡数量相等 */
		ret = m_Query(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex);
		if (!ret)
		{
			ret = 1;
		}
		else
		{
			/* 确认正确的返回类型 */
			ret = SNMP_oidncmp(&varBind[0].name, &MIB_ifEntryType, MIB_ifEntryType.idLength);
			if (!ret)
			{

				dtmp = varBind[0].value.asnValue.number;
				//printf("Interface #%i type : %in", j, dtmp);

				/* Type 6 describes ethernet interfaces */
				if (dtmp == 6)
				{
					/* 确认我们已经在此取得地址 */
					ret = SNMP_oidncmp(&varBind[1].name, &MIB_ifMACEntAddr, MIB_ifMACEntAddr.idLength);
					if ((!ret) && (varBind[1].value.asnValue.address.stream != NULL))
					{
						if ((varBind[1].value.asnValue.address.stream[0] == 0x44) && (varBind[1].value.asnValue.address.stream[1] == 0x45)
							&& (varBind[1].value.asnValue.address.stream[2] == 0x53) && (varBind[1].value.asnValue.address.stream[3] == 0x54)
							&& (varBind[1].value.asnValue.address.stream[4] == 0x00))
						{
							/* 忽略所有的拨号网络接口卡 */
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
							/* 忽略由其他的网络接口卡返回的NULL地址 */
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
	} while (!ret);         /* 发生错误终止。 */


	FreeLibrary(m_hInst);
	/* 解除绑定 */
	SNMP_FreeVarBind(&varBind[0]);
	SNMP_FreeVarBind(&varBind[1]);

	return 0;
}