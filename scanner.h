#pragma once
#include "interface.h"

namespace scanner {
	class Scanner {
	private:

	public:
		~Scanner();
		// PE 파일 경로를 입력받아 .text 섹션의 전체 크기를 구하는 함수
		DWORD getTextSectionSize(const tstring filePath);
		// 매개변수로 입력받은 크기만큼의 메모리를 할당하고, 할당된 메모리에 PE 파일의 .text 섹션 바이트값 전체를 복사하는 함수
		BYTE* getTextSectionBytes(const tstring filePath, DWORD sectionSize);
		//getTextSectionBytes 함수에서 할당한 메모리를 해제하는 함수
		void freeTextSectionBytes(BYTE* sectionBytes);
		// getTextSectionBytes 함수에서 할당한 메모리에 대해 악성코드 패턴을 검사하는 함수
		BOOL scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize);
		// getTextSectionBytes 함수에서 읽어온 바이트 갑 전체를 출력하는 디버깅용 함수
		void printTextSectionBytes(BYTE* sectionBytes, DWORD sectionSize);
		// EntryPointSection 정보를 이용해서 처음 실행되는 코드가 포함된 섹션을 찾는 함수
		DWORD getEntryPointSection(const tstring filePath);
		// PE 파일 경로를 입력받아 DEBUG_FILE_DIRECTORY를 통해 pdb 경로를 구하는 함수
		tstring getPdbPath(const tstring filePath);
	};
}