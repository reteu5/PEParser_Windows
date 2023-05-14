#pragma once
#include "interface.h"

namespace scanner {
	class Scanner {
	private:

	public:
		~Scanner();
		// PE ���� ��θ� �Է¹޾� .text ������ ��ü ũ�⸦ ���ϴ� �Լ�
		DWORD getTextSectionSize(const tstring filePath);
		// �Ű������� �Է¹��� ũ�⸸ŭ�� �޸𸮸� �Ҵ��ϰ�, �Ҵ�� �޸𸮿� PE ������ .text ���� ����Ʈ�� ��ü�� �����ϴ� �Լ�
		BYTE* getTextSectionBytes(const tstring filePath, DWORD sectionSize);
		//getTextSectionBytes �Լ����� �Ҵ��� �޸𸮸� �����ϴ� �Լ�
		void freeTextSectionBytes(BYTE* sectionBytes);
		// getTextSectionBytes �Լ����� �Ҵ��� �޸𸮿� ���� �Ǽ��ڵ� ������ �˻��ϴ� �Լ�
		BOOL scanMalwarePattern(BYTE* sectionBytes, DWORD sectionSize);
		// getTextSectionBytes �Լ����� �о�� ����Ʈ �� ��ü�� ����ϴ� ������ �Լ�
		void printTextSectionBytes(BYTE* sectionBytes, DWORD sectionSize);
		// EntryPointSection ������ �̿��ؼ� ó�� ����Ǵ� �ڵ尡 ���Ե� ������ ã�� �Լ�
		DWORD getEntryPointSection(const tstring filePath);
		// PE ���� ��θ� �Է¹޾� DEBUG_FILE_DIRECTORY�� ���� pdb ��θ� ���ϴ� �Լ�
		tstring getPdbPath(const tstring filePath);
	};
}