#pragma once

#include <windows.h>
#include <tchar.h>
#include <vector>
#include <iostream>

using namespace std;

#if defined(UNICODE) || defined(_UNICODE)
#define tcout wcout
#define OutputDebugStringT OutputDebugStringW
#else
#define tcout cout
#define OutputDebugStringT OutputDebugStringA
#endif

#define LINE_SPLIT _T("\n---------------------------------------------------------------------------------\n")

#define MD5_LENGTH 16

typedef basic_string<TCHAR> tstring;
// Tuple ���� : Base address(exe or DLL), Path(exe or DLL)
typedef vector<tuple<ULONGLONG, tstring>> LoadedDllsInfo;
// Tuple ���� : Name, VirtualAddress, PointerToRawData, SizeOfRawData, Characteristics
typedef tuple<tstring, DWORD, DWORD, DWORD, DWORD> SectionInfo;
// Tuple ���� : function address, function ordinal, function name
typedef vector<tuple<ULONGLONG, DWORD, tstring>> FunctionInfoList;
// Tuple ���� : Name(exe or DLL), vector<FunctionInfoList>
typedef tuple<tstring, FunctionInfoList> ImportExportInfo;
// ���̳ʸ� ������ ������ ���� ���� ����
typedef vector<BYTE> BinaryData;

// PE ������ ���� ����ü ����
typedef struct _PE_STRUCTURE
{
    BOOL m_is32bitPE = FALSE;
    LPVOID m_peBaseAddress = NULL;
    tstring m_peFilePath;
    IMAGE_DOS_HEADER m_peDosHeader = { 0, };
    IMAGE_NT_HEADERS32 m_peNtHeader32 = { 0, };
    IMAGE_NT_HEADERS64 m_peNtHeader64 = { 0, };
    IMAGE_DATA_DIRECTORY m_peDataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = { 0, };
    vector<SectionInfo> m_sectionList;
    vector<ImportExportInfo> m_importList;
    vector<ImportExportInfo> m_exportList;
    vector<ULONGLONG> m_tlsCallbackList;
    tstring m_pdbPath;
}
PE_STRUCTURE, * PPE_STRUCTURE;

// PDB ������ ���� ����ü ����
#define IMAGE_PDB_SIGNATURE 0x53445352 // "RSDS"
typedef struct _IMAGE_PDB_INFO
{
    DWORD Signature;
    BYTE Guid[16];
    DWORD Age;
    CHAR PdbFileName[1];
}
IMAGE_PDB_INFO, * PIMAGE_PDB_INFO;

// PE �Ľ� ��� ����
enum PeElement
{
    PE_HEADER = 0x1000,
    PE_EAT = 0x2000,
    PE_IAT = 0x4000,
    PE_TLS = 0x8000,
    PE_DEBUG = 0x10000,
    PE_ALL = 0xFFFFF
};

// �α� ��½� ����� ���� ����
enum LogLevel
{
    LOG_LEVEL_OFF = 0x0,
    LOG_LEVEL_ALL = 0x1,
    LOG_LEVEL_DEBUG = 0x2,
    LOG_LEVEL_INFO = 0x3,
    LOG_LEVEL_WARN = 0x4,
    LOG_LEVEL_ERROR = 0x5,
    LOG_LEVEL_FATAL = 0x6
};

// �α� ��� ���� ����
enum LogDirection
{
    LOG_DIRECTION_DEBUGVIEW,
    LOG_DIRECTION_CONSOLE
};

// ������Ʈ�� ��Ʈ Ű ����
enum RegRootKey
{
    REG_HKEY_CLASSES_ROOT = reinterpret_cast<ULONGLONG>(HKEY_CLASSES_ROOT),
    REG_HKEY_LOCAL_MACHINE = reinterpret_cast<ULONGLONG>(HKEY_LOCAL_MACHINE),
    REG_HKEY_CURRENT_USER = reinterpret_cast<ULONGLONG>(HKEY_CURRENT_USER),
    REG_HKEY_USERS = reinterpret_cast<ULONGLONG>(HKEY_USERS),
};

// ������Ʈ�� ����� ���� �����ϱ� ���� ���� ���� (������Ʈ�� �� Ÿ��, ������Ʈ�� �� ������)
typedef tuple<DWORD, BinaryData> RegValue;

// �˻��� ������Ʈ�� ��� ����� ���� ���� ���� (������Ʈ�� Key �̸�, ������Ʈ�� Value �̸�(optional), ������Ʈ�� ��Ʈ Ű)
typedef vector<tuple<tstring, tstring, RegRootKey>> RegPathList;

// ������Ʈ���� �����ϴ� ���� ��θ� �����Ͽ� ������� �����ϱ� ���� ���� ���� (���� ���, (������Ʈ�� Key �̸�, ������Ʈ�� Value �̸�, ������Ʈ�� ��Ʈ Ű))
typedef vector<tuple<tstring, const tuple<tstring, tstring, RegRootKey>>> RegFileList;

// ���� ��ĵ�� �Լ� Ÿ�� ����
typedef void(__cdecl* pScanFile)(const tstring scanFilePath);

