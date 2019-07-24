#include "test.h"

string codeTest(string info);

int main()
{
	if (loginInfoDecrypt() == DECRYPT_FAIL) {
		cout << DECRYPT_FAIL << endl;
		return 0;
	}

	for (; UserStack.size() > 0;) {
		cout << "Host:\t\t" << UserStack.top().Host << endl;
		cout << "Username:\t" << UserStack.top().Username << endl;
		cout << "Password:\t" << UserStack.top().Password << endl;
		cout << "================================================" << endl;
		UserStack.pop();
	}

	//cout << getPath() << endl;

	return 0;
}


//Base64¼ÓÃÜ²âÊÔº¯Êý
string codeTest(string info) {
	size_t len = info.size();
	size_t mod = len % 3;
	size_t sub = len / 3;

	if(mod != 0)len += (3 - mod);

	BYTE* unCrypt = (BYTE*)info.c_str();
	size_t enLen = len / 3 * 4 + 1;
	BYTE* enCrypt = (BYTE*)malloc(sizeof(BYTE*) * enLen);
	size_t unCount = 0, enCount = 0;
	
	if (enCrypt != nullptr) {
		for (int i = 0; i < sub; i++) {
			enCrypt[enCount++] = (unCrypt[3 * i] >> 2) + 62;
			enCrypt[enCount] = unCrypt[3 * i] << 6;
			enCrypt[enCount] += unCrypt[3 * i + 1] >> 2;
			enCrypt[enCount] >>= 2;
			enCrypt[enCount++] += 62;

			enCrypt[enCount] = unCrypt[3 * i + 1] << 4;
			enCrypt[enCount] += unCrypt[3 * i + 2] >> 4;
			enCrypt[enCount] >>= 2;
			enCrypt[enCount++] += 62;
			
			enCrypt[enCount] = unCrypt[3 * i + 2] << 2;
			enCrypt[enCount] >>= 2;
			enCrypt[enCount++] += 62;

		}

		if (mod > 0) {
			enCrypt[enCount++] = (unCrypt[3 * sub] >> 2) + 62;
			if (mod == 1) {
				enCrypt[enCount] = unCrypt[3 * sub] << 6;
				enCrypt[enCount] >>= 2;
				enCrypt[enCount++] += 62;
				enCrypt[enCount++] = '=';
				enCrypt[enCount++] = '=';
			}
			else {
				enCrypt[enCount] = unCrypt[3 * sub] << 6;
				enCrypt[enCount] += unCrypt[3 * sub + 1] >> 2;
				enCrypt[enCount] >>= 2;
				enCrypt[enCount++] += 62;

				enCrypt[enCount] = unCrypt[3 * sub + 1] << 4;
				enCrypt[enCount] += unCrypt[3 * sub + 2] >> 4;
				enCrypt[enCount] >>= 2;
				enCrypt[enCount++] += 62;

				enCrypt[enCount++] = '=';
			}
		}

		string out = (char*)enCrypt;
		out = out.substr(0, enCount);
		free(enCrypt);
		return out;
		
	}
	return "code fail";
}