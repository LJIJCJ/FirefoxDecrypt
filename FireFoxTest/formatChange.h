#pragma once
#include <iostream>
#include <Windows.h>

/*
此文件用于个格式转换，将UTF-8转换为gbk编码，以防止中文乱码
*/

char* U2G(const char* utf8)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len + (INT64)1];
	memset(wstr, 0, len + (INT64)1);
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wstr, len);
	len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
	char* str = new char[len + (INT64)1];
	memset(str, 0, len + (INT64)1);
	WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, NULL, NULL);
	if (wstr) delete[] wstr;
	return str;
}