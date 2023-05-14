#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <windows.h>
#include <tchar.h>
#include "typedef.h"
#include "PEparser.h"
#include "scanner.h"

using namespace scanner;
using std::hex;

void scannerMain() {
	//dbg
	tcout << _T("ScannerMain() called") << std::endl;
	
	PEParse::PEParser peclass = PEParse::PEParser();

	HANDLE PEFileMapping = NULL;
	tstring filePath = _T("C:\\Windows\\System32\\shell32.dll");

	PEFileMapping = peclass.getPEFileMapping(filePath);
}

void Scanner::debug(tstring debugmsg) {
	OutputDebugStringT(debugmsg.c_str());
	OutputDebugStringT(_T("\n"));
}

<<<<<<< HEAD
//PE 파일 경로를 입력받아 .text 섹션의 전체 크기를 구하는 함수
DWORD Scanner::getTextSectionSize(const tstring filePath) {
=======
//PE ???? ??θ? ??¹?? .text ?????? ??? ??? ????? ???
DWORD scanner::getTextSectionSize(const tstring filePath) {
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
	PEParse::PEParser peclass = PEParse::PEParser();
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = peclass.getPEFileMapping(filePath);
	peBaseAddress = peclass.getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)peBaseAddress + (WORD)peDosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)(&ntHeader->OptionalHeader) + (ntHeader->FileHeader.SizeOfOptionalHeader));

    if (sectionHeader == NULL) 
        debug(_T("Error: Invalid Image Section Header\n"));
	else {
		for (int i = 0; i < (WORD)ntHeader->FileHeader.NumberOfSections; i++) {
			if ((char*)sectionHeader[i].Name == ".text") 
				// VirtualSize : ???? ???? ???. (NULL ?е? ????? ??.)
				return (DWORD)sectionHeader[i].Misc.VirtualSize;
		}
	}
	return NULL;
}

<<<<<<< HEAD
// 매개변수로 입력받은 크기만큼의 메모리를 할당하고, 할당된 메모리에 PE 파일의 .text 섹션 바이트값 전체를 복사하는 함수
BYTE* Scanner::getTextSectionBytes(const tstring filePath, DWORD sectionSize) {
=======
// ????????? ??¹??? ?????? ???? ??????, ???? ???? PE ?????? .text ???? ??????? ????? ??????? ???
BYTE* scanner::getTextSectionBytes(const tstring filePath, DWORD sectionSize) {
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
	PEParse::PEParser peclass = PEParse::PEParser(); 
	HANDLE peFileMapping = NULL;
	LPVOID peBaseAddress = NULL;
	IMAGE_DOS_HEADER* peDosHeader = NULL;

	peFileMapping = peclass.getPEFileMapping(filePath);
	peBaseAddress = peclass.getPEBaseAddress(peFileMapping);
	peDosHeader = (IMAGE_DOS_HEADER*)peBaseAddress;

	IMAGE_NT_HEADERS32* ntHeader = (IMAGE_NT_HEADERS32*)((BYTE*)peBaseAddress + (WORD)peDosHeader->e_lfanew);
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

<<<<<<< HEAD
//getTextSectionBytes 함수에서 할당한 메모리를 해제하는 함수
void Scanner::freeTextSectionBytes(BYTE* sectionBytes) {
	delete[] sectionBytes;
}

//getTextSectionBytes 함수에서 할당한 메모리에 대해 악성코드 패턴을 검사하는 함수
BOOL Scanner::scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize) {
	// 악성코드 패턴을 저장할 배열
=======
// getTextSectionBytes ??????? ????? ???? ??????? ???
void Scanner::freeTextSectionBytes(BYTE* sectionBytes)
{
	delete[] sectionBytes;
}

// getTextSectionBytes ??????? ????? ???? ???? ?????? ?????? ?????? ???
BOOL Scanner::scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize) {
	// ?????? ?????? ?????? ?迭
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
	BYTE malwarePattern[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56 };
	// ?????? ?????? ???
	DWORD malwarePatternSize = sizeof(malwarePattern) / sizeof(BYTE);

	// ?????? ?????? ????? ????? ??? ?????? ?????? ????? ?????? ????? ??? ??????? FALSE ???
	if (sectionSize < malwarePatternSize) 
		return FALSE;

	// ?????? ?????? ????? ????? ??? ?????? ?????? ????? ???? ?????? ??? ????
	for (int i = 0; i < sectionSize - malwarePatternSize; i++) {
		// ?????? ?????? ???? ???? ?????? ?????? ????? ???????? ???
		if (memcmp(sectionBytes + i, malwarePattern, malwarePatternSize) == 0) {
			// ?????? ????? ?????? TRUE ???
			return TRUE;
		}
	}
	// ?????? ????? ?????? ???? ??? ????? FALSE ???
	return FALSE;
}

<<<<<<< HEAD
// getTextSectionBytes 함수에서 읽어온 바이트 갑 전체를 출력하는 디버깅용 함수
=======
// getTextSectionBytes ??????? ?о?? ????? ?? ????? ?????? ?????? ???
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
void Scanner::debugTextSectionBytes(BYTE* sectionBytes, DWORD sectionSize) {
	for (int i = 0; i < sectionSize; i++) {
		tcout << hex << (int)sectionBytes[i] << _T(" ");
		if (i % 16 == 15) 
			tcout << endl;
	}
}

<<<<<<< HEAD
// EntryPointSection 정보를 이용해서 처음 실행되는 코드가 포함된 섹션을 찾는 함수
=======
//EntryPointSection ?????? ?????? ??? ?????? ??? ????? ?????? ??? ???
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
DWORD Scanner::getEntryPointSection(const tstring filePath) {
	PEParse::PEParser peclass = PEParse::PEParser();
	HANDLE peFileMapping = NULL;
	peFileMapping = peclass.getPEFileMapping(filePath);

}

<<<<<<< HEAD
//PE 파일 경로를 입력받아 DEBUG_FILE_DIRECTORY를 통해 pdb 경로를 구하는 함수
=======
//PE ???? ??θ? ??¹?? DEBUG_FILE_DIRECTORY?? ???? pdb ??θ? ????? ???
>>>>>>> 4b4250e86254b98dd4dfc9d303c716ffc0c5966e
tstring Scanner::getPdbPath(const tstring filePath) {
	PEParse::PEParser peclass = PEParse::PEParser();
	HANDLE peFileMapping = NULL;
	peFileMapping = peclass.getPEFileMapping(filePath);

	if (peFileMapping != NULL) {
		IMAGE_DEBUG_DIRECTORY debugDirectory = {0, };
		DWORD callbackAddress = NULL;

		if ()
	}
}