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


//PE 파일 경로를 입력받아 .text 섹션의 전체 크기를 구하는 함수
DWORD scanner::getTextSectionSize(const tstring filePath) {

}

//EntryPointSection 정보를 이용해서 처음 실행되는 코드가 포함된 섹션을 찾는 함수
DWORD scanner::getEntryPointSection(const tstring filePath);

//PE 파일 경로를 입력받아 DEBUG_FILE_DIRECTORY를 통해 pdb 경로를 구하는 함수
tstring scanner::getPdbPath(const tstring filePath) {

}