#include "stdafx.h"
#include "Encryption.h"
#include "des.h"
#include "AES_Decrypt.h"
#include "md5.h"

#pragma warning(disable:4996)

//将普通字符串转对应的Ascii十六进制字符串
int StrToAsciiHexStr(string str, string& strHex)
{
	int nLen = str.length();
	for (int i = 0; i < nLen; i++)
	{
		char chr[3] = { 0 };
		sprintf_s(chr, "%02X", str[i]);
		strHex += chr;
	}
	return 0;
}

//将Ascii十六进制字符串转对应的普通字符串
int AsciiHexStrToStr(string strHex, string& strDst)
{
	int nLen = strHex.length();
	for (int i = 0; i < nLen; i++)
	{
		char chrVal1 = strHex[i];
		char chrVal2 = 0;
		chrVal2 = (chrVal1 <= '9' && chrVal1 >= '0') ? chrVal1 - '0' : chrVal1 - 'A' + 10;
		chrVal2 <<= 4;
		i++;
		chrVal1 = strHex[i];
		chrVal2 |= ((chrVal1 <= '9' && chrVal1 >= '0') ? chrVal1 - '0' : chrVal1 - 'A' + 10) & 0x0F;
		
		strDst += chrVal2;
	}
	return 0;
}

//二进制转换成16进制字符串,如：0x01 0x02 0x03 -> "010203"
int BinToHexStr(unsigned char* HexStr, unsigned char* Bin, int  BinLen)
{

	char Temp1[3];

	int ret;
	int lens;
	int i = 0;
	lens = BinLen;
	if (lens <= 0)
	{
		return 0;
	}
	int nSize = (lens * 2 + 2) * (int)sizeof(char);
	char* result = new char[nSize];
	memset(result, 0, nSize);

	for (i = 0; i < lens; i++)
	{
		memset(Temp1, 0, sizeof(Temp1));
		ret = sprintf(Temp1, "%X", Bin[i]);
		if (strlen(Temp1) == 1) 
		{
			Temp1[1] = Temp1[0];
			Temp1[0] = '0';
		}
		strcat(result, Temp1);

	}
	strcpy((char*)HexStr, result);

	delete[] result;
	return 2 * i;

}


int HexStrToBin(unsigned char* bin, unsigned char* asc, int len)
{
	char ucChar;
	int nSize = 0;
	len = len / 2 + len % 2;
	//npDest=(char *)bin;
	while (len--) {
		ucChar = (*asc <= '9' && *asc >= '0') ? *asc - '0' : *asc - 'A' + 10;
		ucChar <<= 4;
		asc++;
		ucChar |= ((*asc <= '9' && *asc >= '0') ? *asc - '0' : *asc - 'A' + 10) & 0x0F;
		asc++;
		*bin++ = ucChar;
		nSize++;
	}
	return nSize;
}


/*
	DES_ECB加密/解密
	输入参数：
			DESType=1 加密,=其它 解密
			StrSingleDESKey 8字节密钥,输入格式为Hex字符串,如"0102030405060708"
			SourDataType=1		 加密/解密数据为Hex字符串,如："1122334455667788"
						=其它	 加密/解密数据为ASCII,如："12345678"
			SourDataLen加密/解密数据长度(字节长度),当SourDataType=0时为Hex字节长度,如:"1122334455667788"长度为8
												   当SourDataType=1时为ASCII字节长度,如:"12345678"长度为8
			StrSourData加密/解密数据
	输出参数:
			StrDestData解密/解密结果(Hex字符串格式)
	函数返回:
			0		失败(内存分配错误或输入数据格式错误)
			其它	成功(解密结果字节长度)

*/
extern "C" _declspec(dllexport) int _stdcall SingleDESECB(char DESType, unsigned char* StrSingleDESKey, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData)
{
	int ret;
	unsigned char SingleDESKey[9];

	unsigned char* SourData;
	unsigned char* DestData;
	int SourDataLen, i, j, BlockLen, count = 0;
	int k = 0;
	unsigned char Temp[600];
	//数据加工

	if (strlen((char*)StrSingleDESKey) < 16) return 0;
	HexStrToBin(SingleDESKey, StrSingleDESKey, 16);

	SourDataLen = strlen((char*)StrSourData);
	if (SourDataLen < 0) return 0;
	if (SourDataType == 1)//Hex格式
	{
		if ((SourDataLen % 2) != 0) return 0;
		SourData = (unsigned char*)malloc((SourDataLen / 2 + 8) * sizeof(char));
		DestData = (unsigned char*)malloc((SourDataLen + 9) * sizeof(char));
		if (!SourData) return 0;
		if (!DestData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memset(DestData, 0, sizeof(DestData));
		HexStrToBin(SourData, StrSourData, SourDataLen);
		SourDataLen /= 2;
	}
	else//ASCII格式
	{
		SourData = (unsigned char*)malloc((SourDataLen + 8) * sizeof(char));
		DestData = (unsigned char*)malloc((SourDataLen * 2 + 9) * sizeof(char));
		if (!SourData) return 0;
		if (!DestData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memset(DestData, 0, sizeof(DestData));
		memcpy((char*)SourData, (char*)StrSourData, SourDataLen);
	}

	BlockLen = 240;
	i = SourDataLen / BlockLen;
	j = SourDataLen % BlockLen;
	for (k = 0; k < i; k++) {
		ret = SingleDES(DESType, SingleDESKey, BlockLen, SourData + k * BlockLen, DestData);
		//数据加工
		BinToHexStr(Temp, DestData, ret);
		strcat((char*)StrDestData, (char*)Temp);
		count += ret;
	}
	if (j > 0)
	{
		ret = SingleDES(DESType, SingleDESKey, j, SourData + k * BlockLen, DestData);
		//数据加工
		BinToHexStr(Temp, DestData, ret);
		strcat((char*)StrDestData, (char*)Temp);
		count += ret;
	}
	if (SourData) free(SourData);
	if (DestData) free(DestData);
	return count;
}


/*
	TripleDES_ECB加密/解密
	输入参数：
			DESType=1 加密,=其它 解密
			StrTriDESKey 16字节密钥,输入格式为Hex字符串,如"000102030405060708090A0B0C0D0E0F"
			其它参数定义同DES_ECB

*/
extern "C" _declspec(dllexport) int _stdcall TriDESECB(char DESType, unsigned char* StrTriDESKey, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData)
{
	int ret;
	unsigned char TriDESKey[17];

	unsigned char* SourData;
	unsigned char* DestData;
	int SourDataLen, i, j, BlockLen, count = 0;
	int k = 0;
	unsigned char Temp[600];
	//数据加工
	if (strlen((char*)StrTriDESKey) != 32) return 0;
	HexStrToBin(TriDESKey, StrTriDESKey, strlen((char*)StrTriDESKey));

	SourDataLen = strlen((char*)StrSourData);
	if (SourDataLen < 0) return 0;
	if (SourDataType == 1)//Hex格式
	{
		if ((SourDataLen % 2) != 0) return 0;
		SourData = (unsigned char*)malloc((SourDataLen / 2 + 8) * sizeof(char));
		DestData = (unsigned char*)malloc((SourDataLen + 9) * sizeof(char));
		if (!SourData) return 0;
		if (!DestData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memset(DestData, 0, sizeof(DestData));
		HexStrToBin(SourData, StrSourData, SourDataLen);
		SourDataLen /= 2;
	}
	else//ASCII格式
	{
		SourData = (unsigned char*)malloc((SourDataLen + 8) * sizeof(char));
		DestData = (unsigned char*)malloc((SourDataLen * 2 + 9) * sizeof(char));
		if (!SourData) return 0;
		if (!DestData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memset(DestData, 0, sizeof(DestData));
		memcpy((char*)SourData, (char*)StrSourData, SourDataLen);
	}

	BlockLen = 240;
	i = SourDataLen / BlockLen;
	j = SourDataLen % BlockLen;
	for (k = 0; k < i; k++) {
		ret = TripleDES(DESType, TriDESKey, BlockLen, SourData + k * BlockLen, DestData);
		//数据加工
		BinToHexStr(Temp, DestData, ret);
		strcat((char*)StrDestData, (char*)Temp);
		count += ret;
	}
	if (j > 0)
	{
		ret = TripleDES(DESType, TriDESKey, j, SourData + k * BlockLen, DestData);
		//数据加工
		BinToHexStr(Temp, DestData, ret);
		strcat((char*)StrDestData, (char*)Temp);
		count += ret;
	}

	if (SourData) free(SourData);
	if (DestData) free(DestData);
	return count;
}

extern "C" _declspec(dllexport) int _stdcall TriDESECB_KEY24(char DESType, unsigned char* StrTriDESKey, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData)
{
	int ret;
	unsigned char TriDESKey[17];

	unsigned char* SourData;
	unsigned char* DestData;
	int SourDataLen, i, j, BlockLen, count = 0;
	int k = 0;
	unsigned char Temp[600];
	//数据加工
	if (strlen((char*)StrTriDESKey) < 32) return 0;
	HexStrToBin(TriDESKey, StrTriDESKey, strlen((LPCCH)StrTriDESKey));

	SourDataLen = strlen((char*)StrSourData);
	if (SourDataLen < 0) return 0;
	if (SourDataType == 1)//Hex格式
	{
		if ((SourDataLen % 2) != 0) return 0;
		SourData = (unsigned char*)malloc((SourDataLen / 2 + 8) * sizeof(char));
		DestData = (unsigned char*)malloc((SourDataLen + 9) * sizeof(char));
		if (!SourData) return 0;
		if (!DestData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memset(DestData, 0, sizeof(DestData));
		HexStrToBin(SourData, StrSourData, SourDataLen);
		SourDataLen /= 2;
	}
	else//ASCII格式
	{
		SourData = (unsigned char*)malloc((SourDataLen + 8) * sizeof(char));
		DestData = (unsigned char*)malloc((SourDataLen * 2 + 9) * sizeof(char));
		if (!SourData) return 0;
		if (!DestData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memset(DestData, 0, sizeof(DestData));
		memcpy((char*)SourData, (char*)StrSourData, SourDataLen);
	}

	BlockLen = 240;
	i = SourDataLen / BlockLen;
	j = SourDataLen % BlockLen;
	for (k = 0; k < i; k++) {
		ret = TripleDES_Key24(DESType, TriDESKey, BlockLen, SourData + k * BlockLen, DestData);
		//数据加工
		BinToHexStr(Temp, DestData, ret);
		strcat((char*)StrDestData, (char*)Temp);
		count += ret;
	}
	if (j > 0)
	{
		ret = TripleDES_Key24(DESType, TriDESKey, j, SourData + k * BlockLen, DestData);
		//数据加工
		BinToHexStr(Temp, DestData, ret);
		strcat((char*)StrDestData, (char*)Temp);
		count += ret;
	}

	if (SourData) free(SourData);
	if (DestData) free(DestData);
	return count;
}

/*
	SingleMAC 单MAC计算
	输入参数：
			StrMACKey 8字节密钥,输入格式为Hex字符串,如"0001020304050607"
			StrInitData 初始数据,输入格式为Hex字符串,如"0000000000000000"
			SourDataType,StrSourData定义同上
	输出参数:
			StrDestData 8字节MAC(左4字节为正常情况下的4字节MAC值)

*/
extern "C" _declspec(dllexport) int _stdcall SingleMACCBC(unsigned char* StrMACKey, unsigned char* StrInitData, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData)
{
	unsigned char MACKey[17], InitData[9];

	unsigned char* SourData;
	unsigned char DestData[9];
	int SourDataLen, count = 0;
	//数据加工

	if (strlen((char*)StrMACKey) < 16) return 0;
	HexStrToBin(MACKey, StrMACKey, 16);

	if (strlen((char*)StrInitData) < 16) return 0;
	HexStrToBin(InitData, StrInitData, 16);

	SourDataLen = strlen((char*)StrSourData);
	if (SourDataLen < 0) return 0;
	if (SourDataType == 1)//Hex格式
	{
		if ((SourDataLen % 2) != 0) return 0;
		SourData = (unsigned char*)malloc((SourDataLen / 2 + 8) * sizeof(char));
		if (!SourData) return 0;
		memset(SourData, 0, sizeof(SourData));
		HexStrToBin(SourData, StrSourData, SourDataLen);
		SourDataLen /= 2;
	}
	else//ASCII格式
	{
		SourData = (unsigned char*)malloc((SourDataLen + 8) * sizeof(char));
		if (!SourData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memcpy((char*)SourData, (char*)StrSourData, SourDataLen);
	}

	SingleMAC(MACKey, InitData, SourDataLen, SourData, DestData);

	//数据加工
	BinToHexStr(StrDestData, DestData, 8);
	if (SourData) free(SourData);
	return 8;
}

/*
	TriMACCBC 单MAC计算
	输入参数：
			StrMACKey 16字节密钥,输入格式为Hex字符串,如"000102030405060708090A0B0C0D0E0F"
			StrInitData 初始数据,输入格式为Hex字符串,如"0000000000000000"
			SourDataType,StrSourData定义同上
	输出参数:
			StrDestData 8字节MAC(左4字节为正常情况下的4字节MAC值)

*/
extern "C" _declspec(dllexport) int _stdcall TriMACCBC(unsigned char* StrMACKey, unsigned char* StrInitData, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData)
{
	unsigned char MACKey[17], InitData[9];

	unsigned char* SourData;
	unsigned char DestData[9];
	int SourDataLen;
	//数据加工

	if (strlen((char*)StrMACKey) < 32) return 0;
	HexStrToBin(MACKey, StrMACKey, 32);

	if (strlen((char*)StrInitData) < 16) return 0;
	HexStrToBin(InitData, StrInitData, 16);

	SourDataLen = strlen((char*)StrSourData);
	if (SourDataLen < 0) return 0;
	if (SourDataType == 1)//Hex格式
	{
		if ((SourDataLen % 2) != 0) return 0;
		SourData = (unsigned char*)malloc((SourDataLen / 2 + 8) * sizeof(char));
		if (!SourData) return 0;
		memset(SourData, 0, sizeof(SourData));
		HexStrToBin(SourData, StrSourData, SourDataLen);
		SourDataLen /= 2;
	}
	else//ASCII格式
	{
		SourData = (unsigned char*)malloc((SourDataLen + 8) * sizeof(char));
		if (!SourData) return 0;
		memset(SourData, 0, sizeof(SourData));
		memcpy((char*)SourData, (char*)StrSourData, SourDataLen);
	}

	TripleMAC(MACKey, InitData, SourDataLen, SourData, DestData);

	//数据加工
	BinToHexStr(StrDestData, DestData, 8);
	if (SourData) free(SourData);
	return 8;
}

/*
	解密
	输入参数：
*/
extern "C" _declspec(dllexport) int _stdcall AES_ECB_Decrypt(unsigned char* StrAESKey, unsigned char* StrSourData, unsigned char* StrDestData)
{
	//	int ret;
	unsigned char AESKey[17];

	unsigned char* SourData;
	unsigned char* DestData;
	int SourDataLen, i, j, BlockLen, count = 0;
	unsigned char Temp[600];
	//数据加工
	if (strlen((char*)StrAESKey) < 32) return 0;
	HexStrToBin(AESKey, StrAESKey, 32);

	StrDestData[0] = 0;

	SourDataLen = strlen((char*)StrSourData);
	if (SourDataLen < 0) return 0;

	if ((SourDataLen % 2) != 0) return 0;
	SourData = (unsigned char*)malloc((SourDataLen / 2 + 8) * sizeof(char));
	DestData = (unsigned char*)malloc((SourDataLen + 9) * sizeof(char));
	if (!SourData) return 0;
	if (!DestData) return 0;
	memset(SourData, 0, sizeof(SourData));
	memset(DestData, 0, sizeof(DestData));
	HexStrToBin(SourData, StrSourData, SourDataLen);
	SourDataLen /= 2;

	BlockLen = 16;
	i = SourDataLen % BlockLen;
	if (i != 0)
	{
		for (j = 0; j < (BlockLen - i); j++) {
			SourData[SourDataLen + i] = (unsigned char)0x00;
			SourDataLen++;
		}

	}
	j = SourDataLen % BlockLen;
	if (j != 0) return 0;
	i = SourDataLen / BlockLen;

	for (int k = 0; k < i; k++) {
		//逐块处理数据
		//ret = TripleDES(DESType,TriDESKey,BlockLen,SourData + k * BlockLen,DestData);
		//数据加工
		AES_ECB((char*)AESKey, (char*)SourData + k * BlockLen, (char*)DestData);
		BinToHexStr(Temp, DestData, BlockLen);
		strcat((char*)StrDestData, (char*)Temp);
		count += BlockLen;
	}


	if (SourData) free(SourData);
	if (DestData) free(DestData);

	return count;
}

/*
	计算文件MD5值函数，输入文件完整路径，返回MD5数据
  */
extern "C" _declspec(dllexport) int _stdcall File_MD5_Calc(IN  char* sFilepath, OUT unsigned char* sMD5)
{
	char tMD5[19] = { 0 };
	char szMD5[35] = { 0 };
	int r = MDFile(sFilepath, tMD5);
	if (r != 0) return r;
	BinToHexStr((unsigned char*)szMD5, (unsigned char*)tMD5, 16);
	strcpy((char*)sMD5, szMD5);
	return 0;

}

#pragma warning(default: 4996)