#pragma once

#include <vector>
#include<map>
using namespace std;

class CCheckMachineCode
{
public:
	CCheckMachineCode();
	~CCheckMachineCode();

	int BuildMachineCode(CString& p_strMachineCode);
	int AnalysisMachineCode(CString p_strMachineCode);
	int CheckMachineCode();
	
private:
	int GetCPUID(char* p_pcharCPUID = nullptr);
	void getcpuid(unsigned int* CPUInfo, unsigned int InfoType);
	void getcpuidex(unsigned int* CPUInfo, unsigned int InfoType, unsigned int ECXValue);

	int GetMac(int & p_pnNetNumber,char** p_pchrNetMac);

	int GetMacList(map<CString, int>& p_plistMac);
private:
	map<CString, int> mlistMachineCode;
	
};

