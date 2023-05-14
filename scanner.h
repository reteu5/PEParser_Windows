#pragma once
#include "interface.h"

namespace scanner {
	class Scanner {
	private:

	public:
		~Scanner();
		//PE ���� ��θ� �Է¹޾� .text ������ ��ü ũ�⸦ ���ϴ� �Լ�
		DWORD getTextSectionSize(const tstring filePath);
		//EntryPointSection ������ �̿��ؼ� ó�� ����Ǵ� �ڵ尡 ���Ե� ������ ã�� �Լ�
		DWORD getEntryPointSection(const tstring filePath);
		//PE ���� ��θ� �Է¹޾� DEBUG_FILE_DIRECTORY�� ���� pdb ��θ� ���ϴ� �Լ�
		tstring getPdbPath(const tstring filePath);

		void debug(tstring debugmsg);
		BYTE* getTextSectionBytes(const tstring filePath, DWORD sectionSize);
		void freeTextSectionBytes(BYTE* sectionBytes);
		BOOL scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize);
		void debugTextSectionBytes(BYTE* sectionBytes, DWORD sectionSize);
	};
}