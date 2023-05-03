#pragma once

#include <iostream>

using namespace std;

int StrToAsciiHexStr(string str, string& strHex);
int AsciiHexStrToStr(string strHex, string& strDst);
int BinToHexStr(unsigned char* HexStr, unsigned char* Bin, int  BinLen);
int HexStrToBin(unsigned char* bin, unsigned char* asc, int len);

extern "C" _declspec(dllexport) int _stdcall SingleDESECB(char DESType, unsigned char* StrSingleDESKey, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData);
extern "C" _declspec(dllexport) int _stdcall TriDESECB(char DESType, unsigned char* StrTriDESKey, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData);
extern "C" _declspec(dllexport) int _stdcall TriDESECB_KEY24(char DESType, unsigned char* StrTriDESKey, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData);
extern "C" _declspec(dllexport) int _stdcall SingleMACCBC(unsigned char* StrMACKey, unsigned char* StrInitData, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData);
extern "C" _declspec(dllexport) int _stdcall TriMACCBC(unsigned char* StrMACKey, unsigned char* StrInitData, char SourDataType, unsigned char* StrSourData, unsigned char* StrDestData);
extern "C" _declspec(dllexport) int _stdcall AES_ECB_Decrypt(unsigned char* StrAESKey, unsigned char* StrSourData, unsigned char* StrDestData);
extern "C" _declspec(dllexport) int _stdcall File_MD5_Calc(IN  char* sFilepath, OUT unsigned char* sMD5);