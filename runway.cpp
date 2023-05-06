//#include <iostream>
//#include <string>
//
//using namespace std;
//
//int main() {
//	string str = "Hello World";
//	ULONGLONG* address = (ULONGLONG*)&str;
//	string result = NULL;
//
//	result = copyStringFromAddress(address);
//
//}
//
//string copyStringFromAddress(ULONGLONG* address) {
//	string retString = NULL;
//	string buffer = NULL;
//	int i = 0;
//	do {
//		buffer = (char)address[i];
//		retString.append(buffer);
//		i++;
//	} while (buffer != NULL);
//	return retString;
//}