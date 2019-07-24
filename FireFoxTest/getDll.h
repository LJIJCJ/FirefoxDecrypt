#pragma once
#include "getFileInfo.h"

/*
���ļ����ڼ��ؽ�������������ļ���nss3.dll��
�Լ����ڲ��ĺ�����
*/

//�궨�巵��ֵ
constexpr auto LOAD_FAIL = "load fail";//����dll�ļ�����ʧ��
constexpr auto LOAD_SUCCESS = "load success";//����dll�ļ������ɹ�

//����ö�����ͼ�������	
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

//�����ṹ�弰�����
typedef struct SECItemStr SECItem;
//����ṹ������
struct SECItemStr {
	SECItemType type;
	unsigned char* data;
	size_t len;
};

//����ö�ټ�����
typedef enum _SECStatus {
	SECWouldBlock = -2,
	SECFailure = -1,
	SECSuccess = 0
} SECStatus;

//�������ͱ���
typedef unsigned int PRUint32;//For PL_Base64Decode
typedef void PK11SlotInfo; // For PK11_Authenticate
typedef int PRBool; // For PK11_Authenticate


//������̬����
typedef SECStatus(*fpNSS_Init)(const char* configdir);
typedef char* (*fpPL_Base64Decode)(const char* src, PRUint32 srclen, char* dest);
typedef SECStatus(*fpPK11SDR_Decrypt)(SECItem* data, SECItem* result, void* cx);
typedef SECStatus(*fpPK11_Authenticate)(PK11SlotInfo* slot, PRBool loadCerts, void* wincx);
typedef PK11SlotInfo* (*fpPK11_GetInternalKeySlot)();
typedef void (*fpPK11_FreeSlot)(PK11SlotInfo* slot);
typedef SECStatus(*fpNSS_Shutdown)();

//����ȫ�ֺ���
fpNSS_Init NSS_Init;
fpPL_Base64Decode PL_Base64Decode;
fpPK11SDR_Decrypt PK11SDR_Decrypt;
fpPK11_Authenticate PK11_Authenticate;
fpPK11_GetInternalKeySlot PK11_GetInternalKeySlot;
fpPK11_FreeSlot PK11_FreeSlot;
fpNSS_Shutdown NSS_Shutdown;

//�洢dll�ļ��ľ��
HMODULE nssLib;

//���ڻ�ȡdll�ļ���������dll���䷵��ֵΪ������Ϣ
string loadDll() {
	const char nssLibName[] = "nss3.dll";

	string&& temp = getPath();//ͨ��getPath()������ȡ��װ·��
	if (temp == GET_FAIL)return LOAD_FAIL;

	SetCurrentDirectory(temp.c_str());

	nssLib = LoadLibrary(nssLibName);

	if (nssLib == NULL) {
		return LOAD_FAIL;
	}

	return LOAD_SUCCESS;
}

//���ڼ���dll�ļ��еĺ������䷵��ֵΪ������Ϣ
string loadFunc() {
	if (loadDll() == LOAD_FAIL) return LOAD_FAIL;

	NSS_Init = (fpNSS_Init)GetProcAddress(nssLib, "NSS_Init");
	PL_Base64Decode = (fpPL_Base64Decode)GetProcAddress(nssLib, "PL_Base64Decode");
	PK11SDR_Decrypt = (fpPK11SDR_Decrypt)GetProcAddress(nssLib, "PK11SDR_Decrypt");
	PK11_Authenticate = (fpPK11_Authenticate)GetProcAddress(nssLib, "PK11_Authenticate");
	PK11_GetInternalKeySlot = (fpPK11_GetInternalKeySlot)GetProcAddress(nssLib, "PK11_GetInternalKeySlot");
	PK11_FreeSlot = (fpPK11_FreeSlot)GetProcAddress(nssLib, "PK11_FreeSlot");
	NSS_Shutdown = (fpNSS_Shutdown)GetProcAddress(nssLib, "NSS_Shutdown");

	//��ȷ�˳�
	if (NSS_Init != NULL && PL_Base64Decode != NULL && PK11SDR_Decrypt != NULL && PK11_Authenticate != NULL && PK11_GetInternalKeySlot != NULL && PK11_FreeSlot != NULL && NSS_Shutdown != NULL) {
		return LOAD_SUCCESS;
	}
	//�����˳�
	return LOAD_FAIL;
}