#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <windows.h>
#include <tchar.h>
#include "PEparser.cpp"

using namespace std;

void scannerMain() {
	HANDLE PEFileMapping = NULL;
	tstring filePath = _T("C:\\Windows\\System32\\shell32.dll");

	PEFileMapping = PEParser::getPEFileMapping(filePath);
}


//PE ���� ��θ� �Է¹޾� .text ������ ��ü ũ�⸦ ���ϴ� �Լ�
DWORD scanner::getTextSectionSize(const tstring filePath) {

}

//EntryPointSection ������ �̿��ؼ� ó�� ����Ǵ� �ڵ尡 ���Ե� ������ ã�� �Լ�
DWORD scanner::getEntryPointSection(const tstring filePath);

//PE ���� ��θ� �Է¹޾� DEBUG_FILE_DIRECTORY�� ���� pdb ��θ� ���ϴ� �Լ�
tstring scanner::getPdbPath(const tstring filePath) {

}