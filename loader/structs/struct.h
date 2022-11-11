#pragma once
#include <Windows.h>

// ntdll.dll
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG				NextEntryOffset;
	ULONG				NumberOfThreads;
	BYTE				Reserved1[48];
	UNICODE_STRING		ImageName;
	LONG				BasePriority;
	HANDLE				UniqueProcessId;
	PVOID				Reserved2;
	ULONG				HandleCount;
	ULONG				SessionId;
	PVOID				Reserved3;
	SIZE_T				PeakVirtualSize;
	SIZE_T				VirtualSize;
	ULONG				Reserved4;
	SIZE_T				PeakWorkingSetSize;
	SIZE_T				WorkingSetSize;
	PVOID				Reserved5;
	SIZE_T				QuotaPagedPoolUsage;
	PVOID				Reserved6;
	SIZE_T				QuotaNonPagedPoolUsage;
	SIZE_T				PagefileUsage;
	SIZE_T				PeakPagefileUsage;
	SIZE_T				PrivatePageCount;
	LARGE_INTEGER		Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	struct _PEB_LDR_DATA* Ldr;                                              //0x18
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ProcessImagesHotPatched : 1;                                //0x50
			ULONG ReservedBits0 : 24;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	struct _UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	struct _LIST_ENTRY FlsListHead;                                         //0x328
	VOID* FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	struct _LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
	struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
	union
	{
		ULONG LeapSecondFlags;                                              //0x7c0
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x7c0
			ULONG Reserved : 31;                                              //0x7c0
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x7c4
} PEB, * PPEB;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _EXT_PARAMS
{
	DWORD64 Type;
	PVOID Addr;
} EXT_PARAMS, * PEXT_PARAMS;

typedef struct _KERNELCALLBACKTABLE_T
{
	ULONG_PTR __fnCOPYDATA;
	ULONG_PTR __fnCOPYGLOBALDATA;
	ULONG_PTR __fnDWORD;
	ULONG_PTR __fnNCDESTROY;
	ULONG_PTR __fnDWORDOPTINLPMSG;
	ULONG_PTR __fnINOUTDRAG;
	ULONG_PTR __fnGETTEXTLENGTHS;
	ULONG_PTR __fnINCNTOUTSTRING;
	ULONG_PTR __fnPOUTLPINT;
	ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
	ULONG_PTR __fnINLPCREATESTRUCT;
	ULONG_PTR __fnINLPDELETEITEMSTRUCT;
	ULONG_PTR __fnINLPDRAWITEMSTRUCT;
	ULONG_PTR __fnPOPTINLPUINT;
	ULONG_PTR __fnPOPTINLPUINT2;
	ULONG_PTR __fnINLPMDICREATESTRUCT;
	ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
	ULONG_PTR __fnINLPWINDOWPOS;
	ULONG_PTR __fnINOUTLPPOINT5;
	ULONG_PTR __fnINOUTLPSCROLLINFO;
	ULONG_PTR __fnINOUTLPRECT;
	ULONG_PTR __fnINOUTNCCALCSIZE;
	ULONG_PTR __fnINOUTLPPOINT5_;
	ULONG_PTR __fnINPAINTCLIPBRD;
	ULONG_PTR __fnINSIZECLIPBRD;
	ULONG_PTR __fnINDESTROYCLIPBRD;
	ULONG_PTR __fnINSTRING;
	ULONG_PTR __fnINSTRINGNULL;
	ULONG_PTR __fnINDEVICECHANGE;
	ULONG_PTR __fnPOWERBROADCAST;
	ULONG_PTR __fnINLPUAHDRAWMENU;
	ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
	ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
	ULONG_PTR __fnOUTDWORDINDWORD;
	ULONG_PTR __fnOUTLPRECT;
	ULONG_PTR __fnOUTSTRING;
	ULONG_PTR __fnPOPTINLPUINT3;
	ULONG_PTR __fnPOUTLPINT2;
	ULONG_PTR __fnSENTDDEMSG;
	ULONG_PTR __fnINOUTSTYLECHANGE;
	ULONG_PTR __fnHkINDWORD;
	ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
	ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
	ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
	ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
	ULONG_PTR __fnHkINLPMSG;
	ULONG_PTR __fnHkINLPRECT;
	ULONG_PTR __fnHkOPTINLPEVENTMSG;
	ULONG_PTR __xxxClientCallDelegateThread;
	ULONG_PTR __ClientCallDummyCallback;
	ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
	ULONG_PTR __fnOUTLPCOMBOBOXINFO;
	ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
	ULONG_PTR __xxxClientCallDevCallbackCapture;
	ULONG_PTR __xxxClientCallDitThread;
	ULONG_PTR __xxxClientEnableMMCSS;
	ULONG_PTR __xxxClientUpdateDpi;
	ULONG_PTR __xxxClientExpandStringW;
	ULONG_PTR __ClientCopyDDEIn1;
	ULONG_PTR __ClientCopyDDEIn2;
	ULONG_PTR __ClientCopyDDEOut1;
	ULONG_PTR __ClientCopyDDEOut2;
	ULONG_PTR __ClientCopyImage;
	ULONG_PTR __ClientEventCallback;
	ULONG_PTR __ClientFindMnemChar;
	ULONG_PTR __ClientFreeDDEHandle;
	ULONG_PTR __ClientFreeLibrary;
	ULONG_PTR __ClientGetCharsetInfo;
	ULONG_PTR __ClientGetDDEFlags;
	ULONG_PTR __ClientGetDDEHookData;
	ULONG_PTR __ClientGetListboxString;
	ULONG_PTR __ClientGetMessageMPH;
	ULONG_PTR __ClientLoadImage;
	ULONG_PTR __ClientLoadLibrary;
	ULONG_PTR __ClientLoadMenu;
	ULONG_PTR __ClientLoadLocalT1Fonts;
	ULONG_PTR __ClientPSMTextOut;
	ULONG_PTR __ClientLpkDrawTextEx;
	ULONG_PTR __ClientExtTextOutW;
	ULONG_PTR __ClientGetTextExtentPointW;
	ULONG_PTR __ClientCharToWchar;
	ULONG_PTR __ClientAddFontResourceW;
	ULONG_PTR __ClientThreadSetup;
	ULONG_PTR __ClientDeliverUserApc;
	ULONG_PTR __ClientNoMemoryPopup;
	ULONG_PTR __ClientMonitorEnumProc;
	ULONG_PTR __ClientCallWinEventProc;
	ULONG_PTR __ClientWaitMessageExMPH;
	ULONG_PTR __ClientWOWGetProcModule;
	ULONG_PTR __ClientWOWTask16SchedNotify;
	ULONG_PTR __ClientImmLoadLayout;
	ULONG_PTR __ClientImmProcessKey;
	ULONG_PTR __fnIMECONTROL;
	ULONG_PTR __fnINWPARAMDBCSCHAR;
	ULONG_PTR __fnGETTEXTLENGTHS2;
	ULONG_PTR __fnINLPKDRAWSWITCHWND;
	ULONG_PTR __ClientLoadStringW;
	ULONG_PTR __ClientLoadOLE;
	ULONG_PTR __ClientRegisterDragDrop;
	ULONG_PTR __ClientRevokeDragDrop;
	ULONG_PTR __fnINOUTMENUGETOBJECT;
	ULONG_PTR __ClientPrinterThunk;
	ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
	ULONG_PTR __fnOUTLPSCROLLBARINFO;
	ULONG_PTR __fnINLPUAHDRAWMENU2;
	ULONG_PTR __fnINLPUAHDRAWMENUITEM;
	ULONG_PTR __fnINLPUAHDRAWMENU3;
	ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
	ULONG_PTR __fnINLPUAHDRAWMENU4;
	ULONG_PTR __fnOUTLPTITLEBARINFOEX;
	ULONG_PTR __fnTOUCH;
	ULONG_PTR __fnGESTURE;
	ULONG_PTR __fnPOPTINLPUINT4;
	ULONG_PTR __fnPOPTINLPUINT5;
	ULONG_PTR __xxxClientCallDefaultInputHandler;
	ULONG_PTR __fnEMPTY;
	ULONG_PTR __ClientRimDevCallback;
	ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
	ULONG_PTR __ClientCallLocalMouseHooks;
	ULONG_PTR __xxxClientBroadcastThemeChange;
	ULONG_PTR __xxxClientCallDevCallbackSimple;
	ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
	ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
	ULONG_PTR __fnGETWINDOWDATA;
	ULONG_PTR __fnINOUTSTYLECHANGE2;
	ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} KERNELCALLBACKTABLE;

// win32u.dll
#define FNID_SENDMESSAGE   0x02B1
#define QUERY_WINDOW_UNIQUE_PROCESS_ID	0x00

typedef struct set_clipboard_params
{
	void*	data;
	size_t	size;
	BOOL	cache_only;
	UINT	seqno;
};