#include <iostream>
//#include <iomanip>
//#include <format>
//#include <sstream>
//#include <string>
//#include "varUtils.h"
//#define NEW_LINE tcout << _T("\n") << endl;
//using namespace varUtil;
//using std::endl, std::string;
//
//varUtils::~varUtils() {
//	clean();
//}
//
//void varUtils::clean() {
//	m_processId = NULL;
//	m_FilePath = NULL;
//	m_peBaseAddress = NULL;
//	m_threadHandle = NULL;
//	m_processHandle = NULL;
//
//}
//
//tstring varUtils::readString(LONGLONG addressOfString) {
//	tstring retString = NULL;
//	string buffer = NULL;
//	int i = 0;
//	// addressOfString�� ��� �ּҿ� �����Ͽ� 1����Ʈ�� ���ڿ��� �о�� buffer�� �� ���ھ� append�ϴ� �Լ�
//	do {
//		buffer = (char)addressOfString[i];
//		retString.std::append(buffer);
//		i++;
//	} while (buffer != NULL);
//	//in need to be fixed
//	return retString;
//}