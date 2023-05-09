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
// Tuple 순서 : Base address(exe or DLL), Path(exe or DLL)
typedef vector<tuple<ULONGLONG, tstring>> LoadedDllsInfo;
// Tuple 순서 : Name, VirtualAddress, PointerToRawData, SizeOfRawData, Characteristics
typedef tuple<tstring, DWORD, DWORD, DWORD, DWORD> SectionInfo;
// Tuple 순서 : function address, function ordinal, function name
typedef vector<tuple<ULONGLONG, DWORD, tstring>> FunctionInfoList;
// Tuple 순서 : Name(exe or DLL), vector<FunctionInfoList>
typedef tuple<tstring, FunctionInfoList> ImportExportInfo;
// 바이너리 데이터 저장을 위한 형식 정의
typedef vector<BYTE> BinaryData;

// PE 정보를 담을 구조체 정의
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

// PDB 정보를 담을 구조체 정의
#define IMAGE_PDB_SIGNATURE 0x53445352 // "RSDS"
typedef struct _IMAGE_PDB_INFO
{
    DWORD Signature;
    BYTE Guid[16];
    DWORD Age;
    CHAR PdbFileName[1];
}
IMAGE_PDB_INFO, * PIMAGE_PDB_INFO;

// PE 파싱 대상 정의
enum PeElement
{
    PE_HEADER = 0x1000,
    PE_EAT = 0x2000,
    PE_IAT = 0x4000,
    PE_TLS = 0x8000,
    PE_DEBUG = 0x10000,
    PE_ALL = 0xFFFFF
};

// 로그 출력시 사용할 레벨 정의
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

// 로그 출력 방향 정의
enum LogDirection
{
    LOG_DIRECTION_DEBUGVIEW,
    LOG_DIRECTION_CONSOLE
};

// 레지스트리 루트 키 정의
enum RegRootKey
{
    REG_HKEY_CLASSES_ROOT = reinterpret_cast<ULONGLONG>(HKEY_CLASSES_ROOT),
    REG_HKEY_LOCAL_MACHINE = reinterpret_cast<ULONGLONG>(HKEY_LOCAL_MACHINE),
    REG_HKEY_CURRENT_USER = reinterpret_cast<ULONGLONG>(HKEY_CURRENT_USER),
    REG_HKEY_USERS = reinterpret_cast<ULONGLONG>(HKEY_USERS),
};

// 레지스트리 경로의 값을 저장하기 위한 형식 정의 (레지스트리 값 타입, 레지스트리 값 데이터)
typedef tuple<DWORD, BinaryData> RegValue;

// 검사할 레지스트리 경로 목록을 위한 형식 정의 (레지스트리 Key 이름, 레지스트리 Value 이름(optional), 레지스트리 루트 키)
typedef vector<tuple<tstring, tstring, RegRootKey>> RegPathList;

// 레지스트리에 존재하는 파일 경로를 추출하여 목록으로 저장하기 위한 형식 정의 (파일 경로, (레지스트리 Key 이름, 레지스트리 Value 이름, 레지스트리 루트 키))
typedef vector<tuple<tstring, const tuple<tstring, tstring, RegRootKey>>> RegFileList;

// 파일 스캔용 함수 타입 정의
typedef void(__cdecl* pScanFile)(const tstring scanFilePath);

