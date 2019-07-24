#pragma once
#include "getFileInfo.h"

/*
此文件用于加载解密所需的依赖文件：nss3.dll，
以及其内部的函数。
*/

//宏定义返回值
constexpr auto LOAD_FAIL = "load fail";//加载dll文件或函数失败
constexpr auto LOAD_SUCCESS = "load success";//加载dll文件或函数成功

//声明枚举类型及其内容	
typedef enum {
	siBuffer = 0,
	siClearDataBuffer = 1,
	siCipherDataBuffer = 2,
	siDERCertBuffer = 3,
	siEncodedCertBuffer = 4,
	siDERNameBuffer = 5,
	siEncodedNameBuffer = 6,
	siAsciiNameString = 7,
	siAsciiString = 8,
	siDEROID = 9,
	siUnsignedInteger = 10,
	siUTCTime = 11,
	siGeneralizedTime = 12,
	siVisibleString = 13,
	siUTF8String = 14,
	siBMPString = 15
} SECItemType;

//声明结构体及其别名
typedef struct SECItemStr SECItem;
//定义结构体内容
struct SECItemStr {
	SECItemType type;
	unsigned char* data;
	size_t len;
};

//声明枚举及定义
typedef enum _SECStatus {
	SECWouldBlock = -2,
	SECFailure = -1,
	SECSuccess = 0
} SECStatus;

//数据类型别名
typedef unsigned int PRUint32;//For PL_Base64Decode
typedef void PK11SlotInfo; // For PK11_Authenticate
typedef int PRBool; // For PK11_Authenticate


//声明动态函数
typedef SECStatus(*fpNSS_Init)(const char* configdir);
typedef char* (*fpPL_Base64Decode)(const char* src, PRUint32 srclen, char* dest);
typedef SECStatus(*fpPK11SDR_Decrypt)(SECItem* data, SECItem* result, void* cx);
typedef SECStatus(*fpPK11_Authenticate)(PK11SlotInfo* slot, PRBool loadCerts, void* wincx);
typedef PK11SlotInfo* (*fpPK11_GetInternalKeySlot)();
typedef void (*fpPK11_FreeSlot)(PK11SlotInfo* slot);
typedef SECStatus(*fpNSS_Shutdown)();

//声明全局函数
fpNSS_Init NSS_Init;
fpPL_Base64Decode PL_Base64Decode;
fpPK11SDR_Decrypt PK11SDR_Decrypt;
fpPK11_Authenticate PK11_Authenticate;
fpPK11_GetInternalKeySlot PK11_GetInternalKeySlot;
fpPK11_FreeSlot PK11_FreeSlot;
fpNSS_Shutdown NSS_Shutdown;

//存储dll文件的句柄
HMODULE nssLib;

//用于获取dll文件，并加载dll，其返回值为报错信息
string loadDll() {
	const char nssLibName[] = "nss3.dll";

	string&& temp = getPath();//通过getPath()函数获取安装路径
	if (temp == GET_FAIL)return LOAD_FAIL;

	SetCurrentDirectory(temp.c_str());

	nssLib = LoadLibrary(nssLibName);

	if (nssLib == NULL) {
		return LOAD_FAIL;
	}

	return LOAD_SUCCESS;
}

//用于加载dll文件中的函数，其返回值为报错信息
string loadFunc() {
	if (loadDll() == LOAD_FAIL) return LOAD_FAIL;

	NSS_Init = (fpNSS_Init)GetProcAddress(nssLib, "NSS_Init");
	PL_Base64Decode = (fpPL_Base64Decode)GetProcAddress(nssLib, "PL_Base64Decode");
	PK11SDR_Decrypt = (fpPK11SDR_Decrypt)GetProcAddress(nssLib, "PK11SDR_Decrypt");
	PK11_Authenticate = (fpPK11_Authenticate)GetProcAddress(nssLib, "PK11_Authenticate");
	PK11_GetInternalKeySlot = (fpPK11_GetInternalKeySlot)GetProcAddress(nssLib, "PK11_GetInternalKeySlot");
	PK11_FreeSlot = (fpPK11_FreeSlot)GetProcAddress(nssLib, "PK11_FreeSlot");
	NSS_Shutdown = (fpNSS_Shutdown)GetProcAddress(nssLib, "NSS_Shutdown");

	//正确退出
	if (NSS_Init != NULL && PL_Base64Decode != NULL && PK11SDR_Decrypt != NULL && PK11_Authenticate != NULL && PK11_GetInternalKeySlot != NULL && PK11_FreeSlot != NULL && NSS_Shutdown != NULL) {
		return LOAD_SUCCESS;
	}
	//错误退出
	return LOAD_FAIL;
}