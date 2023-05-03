#pragma once

int SingleDES(char DESType, unsigned char* SingleDESKey, int SourDataLen, unsigned char* SourData, unsigned char* DestData);
int TripleDES(char DESType, unsigned char* TripleDESKey, int SourDataLen, unsigned char* SourData, unsigned char* DestData);
int SingleMAC(unsigned char* SingleMACKey, unsigned char* InitData, int SourDataLen, unsigned char* SourData, unsigned char* MACData);
int TripleMAC(unsigned char* TriMACKey, unsigned char* InitData, int SourDataLen, unsigned char* SourData, unsigned char* MACData);
int TripleDES_Key24(char DESType, unsigned char* TripleDESKey, int SourDataLen, unsigned char* SourData, unsigned char* DestData);