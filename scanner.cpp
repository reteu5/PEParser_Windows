#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <windows.h>
#include <tchar.h>
#include "PEparser.cpp"

using namespace scanner;

void scannerMain() {
	// dbg
	tcout << _T("scannerMain") << endl;
	HANDLE PEFileMapping = NULL;
	tstring filePath = _T("C:\\Windows\\System32\\shell32.dll");

	PEFileMapping = PEParser::getPEFileMapping(filePath);
}


//PE 파일 경로를 입력받아 .text 섹션의 전체 크기를 구하는 함수
DWORD Scanner::getTextSectionSize(const tstring filePath) {
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = PEParser::getPEFileMapping(filePath);
	peBaseAddress = PEParser::getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)m_peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));

    if (sectionHeader == NULL) 
        debug(_T("Error: Invalid Image Section Header\n"));
	else {
		for (int i = 0; i < (WORD)ntHeader->FileHeader.NumberOfSections; i++) {
			if ((char*)sectionHeader[i].Name == ".text") 
				// VirtualSize : 메모리에 탑재된 크기. (NULL 패딩 제외된 것.)
				return (DWORD)sectionHeader[i].Misc.VirtualSize;
		}
	}
	return NULL;
}

// 매개변수로 입력받은 크기만큼의 메모리를 할당하고, 할당된 메모리에 PE 파일의 .text 섹션 바이트값 전체를 복사하는 함수
BYTE* Scanner::getTextSectionBytes(const tstring filePath, DWORD sectionSize) {
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = PEParser::getPEFileMapping(filePath);
	peBaseAddress = PEParser::getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)m_peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)m_peBaseAddress + (WORD)m_peDosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));

	if (sectionHeader == NULL) 
		debug(_T("Error: Invalid Image Section Header\n"));
	else {
		for (int i = 0; i < (WORD)ntHeader->FileHeader.NumberOfSections; i++) {
			if ((char*)sectionHeader[i].Name == ".text") {
				BYTE* sectionBytes = new BYTE[sectionSize];
				memcpy(sectionBytes, (BYTE*)peBaseAddress + sectionHeader[i].VirtualAddress, sectionSize);
				return sectionBytes;
			}
		}
	}
	return NULL;
}

// getTextSectionBytes 함수에서 할당한 메모리를 해제하는 함수
void Scanner::freeTextSectionBytes(BYTE* sectionBytes)
{
	delete[] sectionBytes;
}

// getTextSectionBytes 함수에서 할당한 메모리에 대해 악성코드 패턴을 검사하는 함수
BOOL Scanner::scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize) {
	// 악성코드 패턴을 저장할 배열
	BYTE malwarePattern[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56 };
	// 악성코드 패턴의 크기
	DWORD malwarePatternSize = sizeof(malwarePattern) / sizeof(BYTE);

	// 악성코드 패턴을 검사할 메모리의 크기가 악성코드 패턴의 크기보다 작으면 검사할 필요가 없으므로 FALSE 반환
	if (sectionSize < malwarePatternSize) 
		return FALSE;

	// 악성코드 패턴을 검사할 메모리의 크기가 악성코드 패턴의 크기보다 크거나 같으면 검사 시작
	for (int i = 0; i < sectionSize - malwarePatternSize; i++) {
		// 악성코드 패턴의 크기만큼 메모리를 검사해서 악성코드 패턴과 일치하는지 검사
		if (memcmp(sectionBytes + i, malwarePattern, malwarePatternSize) == 0) {
			// 악성코드 패턴과 일치하면 TRUE 반환
			return TRUE;
		}
	}
	// 악성코드 패턴과 일치하는 것을 찾지 못하면 FALSE 반환
	return FALSE;
}

// getTextSectionBytes 함수에서 읽어온 바이트 갑 전체를 출력하는 디버깅용 함수
void Scanner::debugTextSectionBytes(BYTE* sectionBytes, DWORD sectionSize) {
	for (int i = 0; i < sectionSize; i++) {
		tcout << hex << (int)sectionBytes[i] << _T(" ");
		if (i % 16 == 15) 
			tcout << endl;
	}
}

//EntryPointSection 정보를 이용해서 처음 실행되는 코드가 포함된 섹션을 찾는 함수
DWORD Scanner::getEntryPointSection(const tstring filePath) {
	HANDLE peFileMapping = NULL;
	peFileMapping = PEParser::getPEFileMapping(filePath);
}

//PE 파일 경로를 입력받아 DEBUG_FILE_DIRECTORY를 통해 pdb 경로를 구하는 함수
tstring Scanner::getPdbPath(const tstring filePath) {
	HANDLE peFileMapping = NULL;
	peFileMapping = PEParser::getPEFileMapping(filePath);

	
}