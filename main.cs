using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

/*
|| AUTHOR Arsium ||
|| github : https://github.com/arsium       ||
|| Please let this credit for all time I passed to work on it ||
||
|| GetModuleBaseAddress ||
|| Thx to : https://github.com/stevemk14ebr/PolyHook_2_0/blob/master/sources/IatHook.cpp#L51 to point me in the right direction ||
||
|| GetExportAddress ||
|| Based on : https://blog.xpnsec.com/weird-ways-to-execute-dotnet/ ||
|| Based on : https://social.msdn.microsoft.com/Forums/azure/zh-CN/6490b46f-909f-43b0-9cb9-220d0b4812fc/how-to-get-functions-exported-from-a-dll-file?forum=vbinterop ||
*/

namespace CustomGetProcAndGetModule
{
    internal class Program
    {
        #region "Native Imports"
        #region "Enums"
        public enum Characteristics : ushort
        {
            IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
            IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
            IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
            IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
            IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010,
            IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
            IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
            IMAGE_FILE_32BIT_MACHINE = 0x0100,
            IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
            IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
            IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
            IMAGE_FILE_SYSTEM = 0x1000,
            IMAGE_FILE_DLL = 0x2000,
            IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
            IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
        }
        public enum Machine : ushort
        {
            IMAGE_FILE_MACHINE_UNKNOWN = 0,
            IMAGE_FILE_MACHINE_TARGET_HOST = 0x0001,
            IMAGE_FILE_MACHINE_I386 = 0x014c, // Intel 386.
            IMAGE_FILE_MACHINE_R3000 = 0x0162, // MIPS little-endian, =0x160 big-endian
            IMAGE_FILE_MACHINE_R4000 = 0x0166,// MIPS little-endian
            IMAGE_FILE_MACHINE_R10000 = 0x0168,// MIPS little-endian
            IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169,// MIPS little-endian WCE v2
            IMAGE_FILE_MACHINE_ALPHA = 0x0184,// Alpha_AXP
            IMAGE_FILE_MACHINE_SH3 = 0x01a2,// SH3 little-endian
            IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
            IMAGE_FILE_MACHINE_SH3E = 0x01a4, // SH3E little-endian
            IMAGE_FILE_MACHINE_SH4 = 0x01a6, // SH4 little-endian
            IMAGE_FILE_MACHINE_SH5 = 0x01a8,// SH5
            IMAGE_FILE_MACHINE_ARM = 0x01c0,// ARM Little-Endian
            IMAGE_FILE_MACHINE_THUMB = 0x01c2,// ARM Thumb/Thumb-2 Little-Endian
            IMAGE_FILE_MACHINE_ARMNT = 0x01c4,// ARM Thumb-2 Little-Endian
            IMAGE_FILE_MACHINE_AM33 = 0x01d3,
            IMAGE_FILE_MACHINE_POWERPC = 0x01F0, // IBM PowerPC Little-Endian
            IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
            IMAGE_FILE_MACHINE_IA64 = 0x0200, // Intel 64
            IMAGE_FILE_MACHINE_MIPS16 = 0x0266, // MIPS
            IMAGE_FILE_MACHINE_ALPHA64 = 0x0284,// ALPHA64
            IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,// MIPS
            IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,// MIPS
            IMAGE_FILE_MACHINE_AXP64 = IMAGE_FILE_MACHINE_ALPHA64,
            IMAGE_FILE_MACHINE_TRICORE = 0x0520,// Infineon
            IMAGE_FILE_MACHINE_CEF = 0x0CEF,
            IMAGE_FILE_MACHINE_EBC = 0x0EBC, // EFI Byte Code
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,// AMD64 (K8)
            IMAGE_FILE_MACHINE_M32R = 0x9041,// M32R little-endian
            IMAGE_FILE_MACHINE_ARM64 = 0xAA64,// ARM64 Little-Endian
            IMAGE_FILE_MACHINE_CEE = 0xC0EE
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_OS2_CUI = 5,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
            IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG = 17
        }
        public enum DllCharacteristics : ushort
        {
            IMAGE_LIBRARY_PROCESS_INIT = 0x0001,//RES_0
            IMAGE_LIBRARY_PROCESS_TERM = 0x0002,//RES_1
            IMAGE_LIBRARY_THREAD_INIT = 0x0004,//RES_2
            IMAGE_LIBRARY_THREAD_TERM = 0x0008,//RES_3
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000,//RES_4
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,      //PE32
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,      //PE32+
            IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107
        }
        public enum NtStatus : uint
        {
            STATUS_SUCCESS = 0x00000000
        }

        public enum ProcessInformationClass
        {
            ProcessBasicInformation = 0,   
        }

        [Flags]
        public enum PebFlags : byte
        {
            None = 0,
            ImageUsesLargePages = 0x01,
            IsProtectedProcess = 0x02,
            IsImageDynamicallyRelocated = 0x04,
            SkipPatchingUser32Forwarders = 0x08,
            IsPackagedProcess = 0x10,
            IsAppContainer = 0x20,
            IsProtectedProcessLight = 0x40,
            IsLongPathAwareProcess = 0x80,
        }

        [Flags]
        public enum SubSystemType4Bytes : uint
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_OS2_CUI = 5,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
            IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG = 17
        }
        #endregion
        #region "Structures"
        [StructLayout(LayoutKind.Sequential)]
        public struct ImageDosHeader
        {
            public ushort e_magic;    // Magic number
            public ushort e_cblp;     // Bytes on last page of file
            public ushort e_cp;       // Pages in file
            public ushort e_crlc;     // Relocations
            public ushort e_cparhdr;  // Size of header in paragraphs
            public ushort e_minalloc; // Minimum extra paragraphs needed
            public ushort e_maxalloc; // Maximum extra paragraphs needed
            public ushort e_ss;       // Initial (relative) SS value
            public ushort e_sp;       // Initial SP value
            public ushort e_csum;     // Checksum
            public ushort e_ip;       // Initial IP value
            public ushort e_cs;       // Initial (relative) CS value
            public ushort e_lfarlc;   // File address of relocation table
            public ushort e_ovno;     // Overlay number
            public ushort e_res1a, e_res1b, e_res1c, e_res1d; // Reserved words //    WORD   e_res[4];
            public ushort e_oemid;    // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;  // OEM information; e_oemid specific
            public ushort e_res2a, e_res2b, e_res2c, e_res2d, e_res2e, e_res2f, e_res2g, e_res2h, e_res2i, e_res2j; // Reserved words     WORD   e_res2[10];  
            public int e_lfanew;      // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PebLdrData
        {
            public uint Length;
            public bool Initialized;
            public IntPtr SsHandle;
            public ListEntry InLoadOrderModuleList;
            public ListEntry InMemoryOrderModuleList;
            public ListEntry InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LdrDataTableEntry
        {
            public ListEntry InLoadOrderLinks;
            public ListEntry InMemoryOrderLinks;
            public ListEntry InInitializationOrderLinks;
            public IntPtr DllBase; //ModuleBaseAddress()
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public UnicodeString FullDllName;
            public UnicodeString BaseDllName;
            public uint Flags;
            public ushort LoadCount;
            public ushort TlsIndex;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ListEntry
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UnicodeString : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UnicodeString(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessBasicInformation
        {
            public NtStatus ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LargeInteger
        {
            [FieldOffset(0)] public long QuadPart;

            [FieldOffset(0)] public uint LowPart;
            [FieldOffset(4)] public int HighPart;

            [FieldOffset(0)] public int LowPartAsInt;
            [FieldOffset(0)] public uint LowPartAsUInt;

            [FieldOffset(4)] public int HighPartAsInt;
            [FieldOffset(4)] public uint HighPartAsUInt;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct PEB32
        {
            [MarshalAs(UnmanagedType.U1)]
            public bool InheritedAddressSpace;
            [MarshalAs(UnmanagedType.U1)]
            public bool ReadImageFileExecOptions;
            [MarshalAs(UnmanagedType.U1)]
            public bool BeingDebugged;
            public PebFlags PebFlags;
            public int Mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr Ldr; // PPEB_LDR_DATA
            public IntPtr ProcessParameters; // PRTL_USER_PROCESS_PARAMETERS
            public IntPtr SubSystemData;//int
            public IntPtr ProcessHeap;//int
            public IntPtr FastPebLock;//int -> PRTL_CRITICAL_SECTION

            public IntPtr FastPebLockRoutine;// -> PPEBLOCKROUTINE
            public IntPtr FastPebUnlockRoutine;
            public uint EnvironmentUpdateCount;
            public IntPtr KernelCallbackTable;
            public uint Reserved1;
            public uint Reserved2;
            public IntPtr FreeList;// -> PPEB_FREE_BLOCK
            public uint TlsExpansionCounter;
            public IntPtr TlsBitmap; // -> PRTL_BITMAP
            public uint TlsBitmapBits1;
            public uint TlsBitmapBits2;
            public IntPtr ReadOnlySharedMemoryBase;
            public IntPtr ReadOnlySharedMemoryHeap;
            public void** ReadOnlyStaticServerData;

            public IntPtr AnsiCodePageData;                  /* 058/0a0 */
            public IntPtr OemCodePageData;                   /* 05c/0a8 */
            public IntPtr UnicodeCaseTableData;              /* 060/0b0 */
            public uint NumberOfProcessors;
            public uint NtGlobalFlags;


            ///
            public LargeInteger CriticalSectionTimeout;            /* LARGE_INTEGER */
            public UIntPtr HeapSegmentReserve;                /* SIZE_T */
            public UIntPtr HeapSegmentCommit;                 /* SIZE_T */
            public UIntPtr HeapDeCommitTotalFreeThreshold;    /* SIZE_T */
            public UIntPtr HeapDeCommitFreeBlockThreshold;    /* SIZE_T */
            public uint NumberOfHeaps;                     /* 088/0e8 */
            public uint MaximumNumberOfHeaps;              /* 08c/0ec */
            public void** ProcessHeaps;                      /* PVOID* */
            IntPtr GdiSharedHandleTable;              /* PVOID */
            IntPtr ProcessStarterHelper;              /* PVOID */
            IntPtr GdiDCAttributeList;                /* PVOID */
            IntPtr LoaderLock;                        /* PVOID */
            public uint OSMajorVersion;                    /* ULONG */
            public uint OSMinorVersion;                    /* ULONG */
            public uint OSBuildNumber;                     /* ULONG */ //WORKS
            public uint OSPlatformId;                      /* ULONG */
            public SubSystemType4Bytes ImageSubSystem;                    /* ULONG */
            public uint ImageSubSystemMajorVersion;        /* ULONG */
            public uint ImageSubSystemMinorVersion;        /* ULONG */
            public uint ImageProcessAffinityMask;          /* ULONG */

            /*  public int AtlThunkSListPtr;
              public int IFEOKey;
              public PebCrossProcessFlags CrossProcessFlags;
              public int UserSharedInfoPtr;
              public int SystemReserved;
              public int AtlThunkSListPtr32;
              public int ApiSetMap;*/
        }
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct PEB64
        {
            [MarshalAs(UnmanagedType.U1)]
            public bool InheritedAddressSpace;
            [MarshalAs(UnmanagedType.U1)]
            public bool ReadImageFileExecOptions;
            [MarshalAs(UnmanagedType.U1)]
            public bool BeingDebugged;
            public PebFlags PebFlags;
            public IntPtr Mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr Ldr; // PPEB_LDR_DATA
            public IntPtr ProcessParameters; // PRTL_USER_PROCESS_PARAMETERS
            public IntPtr SubSystemData;
            public IntPtr ProcessHeap;
            public IntPtr FastPebLock;

            public IntPtr FastPebLockRoutine;// -> PPEBLOCKROUTINE
            public IntPtr FastPebUnlockRoutine;
            public uint EnvironmentUpdateCount;
            public IntPtr KernelCallbackTable;
            public uint Reserved1;
            public uint Reserved2;
            public IntPtr FreeList;// -> PPEB_FREE_BLOCK
            public uint TlsExpansionCounter;
            public IntPtr TlsBitmap; // -> PRTL_BITMAP
            public uint TlsBitmapBits1;
            public uint TlsBitmapBits2;
            public IntPtr ReadOnlySharedMemoryBase;
            public IntPtr ReadOnlySharedMemoryHeap;
            public void** ReadOnlyStaticServerData;

            public IntPtr AnsiCodePageData;                  /* 058/0a0 */
            public IntPtr OemCodePageData;                   /* 05c/0a8 */
            public IntPtr UnicodeCaseTableData;              /* 060/0b0 */
            public uint NumberOfProcessors;
            public uint NtGlobalFlags;


            ///
            public LargeInteger CriticalSectionTimeout;            /* LARGE_INTEGER */
            public UIntPtr HeapSegmentReserve;                /* SIZE_T */
            public UIntPtr HeapSegmentCommit;                 /* SIZE_T */
            public UIntPtr HeapDeCommitTotalFreeThreshold;    /* SIZE_T */
            public UIntPtr HeapDeCommitFreeBlockThreshold;    /* SIZE_T */
            public uint NumberOfHeaps;                     /* 088/0e8 */
            public uint MaximumNumberOfHeaps;              /* 08c/0ec */
            public void** ProcessHeaps;                      /* PVOID* */
            IntPtr GdiSharedHandleTable;              /* PVOID */
            IntPtr ProcessStarterHelper;              /* PVOID */
            IntPtr GdiDCAttributeList;                /* PVOID */
            IntPtr LoaderLock;                        /* PVOID */
            public uint OSMajorVersion;                    /* ULONG */
            public uint OSMinorVersion;                    /* ULONG */
            public uint OSBuildNumber;                     /* ULONG */ //WORKS
            public uint OSPlatformId;                      /* ULONG */
            public SubSystemType4Bytes ImageSubSystem;                    /* ULONG */
            public uint ImageSubSystemMajorVersion;        /* ULONG */
            public uint ImageSubSystemMinorVersion;        /* ULONG */
            public uint ImageProcessAffinityMask;          /* ULONG */

            /*  public IntPtr AtlThunkSListPtr;
            public IntPtr IFEOKey;
            public PebCrossProcessFlags CrossProcessFlags;
            public IntPtr UserSharedInfoPtr;//or KernelCallbackTable
            public int SystemReserved;
            public int AtlThunkSListPtr32;//SpareUlong
            public IntPtr ApiSetMap;*/
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ImageOptionalHeader32
        {
            public MagicType Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBaseLong;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public SubSystemType Subsystem;
            public DllCharacteristics DllCharacteristics;
            public IntPtr SizeOfStackReserve;
            public IntPtr SizeOfStackCommit;
            public IntPtr SizeOfHeapReserve;
            public IntPtr SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public ImageDataDirectory ExportTable;//ImageExportDirectory
            public ImageDataDirectory ImportTable;
            public ImageDataDirectory ResourceTable;//ImageResourceDirectory
            public ImageDataDirectory ExceptionTable;
            public ImageDataDirectory CertificateTable;
            public ImageDataDirectory BaseRelocationTable;
            public ImageDataDirectory Debug;//ImageDebugDirectory
            public ImageDataDirectory Architecture;
            public ImageDataDirectory GlobalPtr;
            public ImageDataDirectory TLSTable;
            public ImageDataDirectory LoadConfigTable;
            public ImageDataDirectory BoundImport;
            public ImageDataDirectory IAT;
            public ImageDataDirectory DelayImportDescriptor;
            public ImageDataDirectory CLRRuntimeHeader;
            public ImageDataDirectory Reserved;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ImageOptionalHeader64
        {
            public MagicType Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBaseLong;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public SubSystemType Subsystem;
            public DllCharacteristics DllCharacteristics;
            public IntPtr SizeOfStackReserve;
            public IntPtr SizeOfStackCommit;
            public IntPtr SizeOfHeapReserve;
            public IntPtr SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            public ImageDataDirectory ExportTable;//ImageExportDirectory
            public ImageDataDirectory ImportTable;
            public ImageDataDirectory ResourceTable;//ImageResourceDirectory
            public ImageDataDirectory ExceptionTable;
            public ImageDataDirectory CertificateTable;
            public ImageDataDirectory BaseRelocationTable;
            public ImageDataDirectory Debug;//ImageDebugDirectory
            public ImageDataDirectory Architecture;
            public ImageDataDirectory GlobalPtr;
            public ImageDataDirectory TLSTable;
            public ImageDataDirectory LoadConfigTable;
            public ImageDataDirectory BoundImport;
            public ImageDataDirectory IAT;
            public ImageDataDirectory DelayImportDescriptor;
            public ImageDataDirectory CLRRuntimeHeader;
            public ImageDataDirectory Reserved;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ImageDataDirectory
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct ImageExportDirectory
        {
            [FieldOffset(0)]
            public int Characteristics;
            [FieldOffset(4)]
            public int TimeDateStamp;
            [FieldOffset(8)]
            public short MajorVersion;
            [FieldOffset(10)]
            public short MinorVersion;
            [FieldOffset(12)]
            public int NameRVA;
            [FieldOffset(16)]
            public int OrdinalBase;
            [FieldOffset(20)]
            public int NumberOfFunctions;      //Address TableEntries
            [FieldOffset(24)]
            public int NumberOfNames;          // Number of Name Pointers
            [FieldOffset(28)]
            public int AddressOfFunctions;     // RVA from base of image Export Address Table RVA 
            [FieldOffset(32)]
            public int AddressOfNames;         // RVA from base of image Name Pointer RVA
            [FieldOffset(36)]
            public int AddressOfNameOrdinals;  // RVA from base of image OrdinalTable RVA
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ImageFileHeader
        {
            public Machine Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public Characteristics Characteristics;
        }

        #endregion
        #region "Functions"
        [DllImport("ntdll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern NtStatus NtQueryInformationProcess
          (
              IntPtr ProcessHandle,
              ProcessInformationClass ProcessInforationClass,
              IntPtr ProcessInformation,
              uint ProcessInformationLength,
              out uint ReturnLength
          );

        #endregion
        #endregion
        public class ExportedFunction
        {
            public int Ordinal { get; set; }
            public string Name { get; set; }
            public int RelativeAddress { get; set; }
            public IntPtr FullAddress { get; set; }
        }

        public static IntPtr GetExportAddress(string moduleName, string functionName)
        {
            Dictionary<int, ExportedFunction> listOfFunctions = new Dictionary<int, ExportedFunction>();

            IntPtr moduleBaseAddr = GetModuleBaseAddress(moduleName, Process.GetCurrentProcess());

            ImageDosHeader dosHeader = (ImageDosHeader)Marshal.PtrToStructure(moduleBaseAddr, typeof(ImageDosHeader));
            if (IntPtr.Size == 4)
            {

                ImageOptionalHeader32 peHeader = (ImageOptionalHeader32)Marshal.PtrToStructure(moduleBaseAddr + dosHeader.e_lfanew + 4 + Marshal.SizeOf(typeof(ImageFileHeader)), typeof(ImageOptionalHeader32));
                ImageExportDirectory exportHeader = (ImageExportDirectory)Marshal.PtrToStructure(moduleBaseAddr + (int)peHeader.ExportTable.VirtualAddress, typeof(ImageExportDirectory));

                IntPtr pNames = IntPtr.Add(moduleBaseAddr, exportHeader.AddressOfNames);
                IntPtr pNameOrdinals = IntPtr.Add(moduleBaseAddr, exportHeader.AddressOfNameOrdinals);
                IntPtr pFunctions = IntPtr.Add(moduleBaseAddr, exportHeader.AddressOfFunctions);

                for (int i = 0; i <= exportHeader.NumberOfFunctions - 1; i++)
                {
                    int rva = Marshal.ReadInt32(pFunctions, i * 4);
                    if (rva != 0)
                    {
                        listOfFunctions.Add(exportHeader.OrdinalBase + i, new ExportedFunction()
                        {
                            Ordinal = exportHeader.OrdinalBase + i,
                            RelativeAddress = rva,
                            FullAddress = (IntPtr)((int)moduleBaseAddr + rva)
                        });
                    }
                }

                for (int i = 0; i <= exportHeader.NumberOfNames - 1; i++)
                {
                    int ordinal = exportHeader.OrdinalBase + Marshal.ReadInt16(pNameOrdinals, i * 2);
                    ExportedFunction entry = listOfFunctions[ordinal];
                    IntPtr nameAddress = IntPtr.Add(moduleBaseAddr, Marshal.ReadInt32(pNames, i * 4));
                    entry.Name = Marshal.PtrToStringAnsi(nameAddress);
                    if (entry.Name == functionName)
                        return entry.FullAddress;
                }
            }
            else
            {

                ImageOptionalHeader64 peHeader = (ImageOptionalHeader64)Marshal.PtrToStructure(moduleBaseAddr + dosHeader.e_lfanew + 4 + Marshal.SizeOf(typeof(ImageFileHeader)), typeof(ImageOptionalHeader64));
                ImageExportDirectory exportHeader = (ImageExportDirectory)Marshal.PtrToStructure(moduleBaseAddr + (int)peHeader.ExportTable.VirtualAddress, typeof(ImageExportDirectory));

                IntPtr pNames = IntPtr.Add(moduleBaseAddr, exportHeader.AddressOfNames);
                IntPtr pNameOrdinals = IntPtr.Add(moduleBaseAddr, exportHeader.AddressOfNameOrdinals);
                IntPtr pFunctions = IntPtr.Add(moduleBaseAddr, exportHeader.AddressOfFunctions);

                for (int i = 0; i <= exportHeader.NumberOfFunctions - 1; i++)
                {
                    int rva = Marshal.ReadInt32(pFunctions, i * 4);
                    if (rva != 0)
                    {
                        listOfFunctions.Add(exportHeader.OrdinalBase + i, new ExportedFunction()
                        {
                            Ordinal = exportHeader.OrdinalBase + i,
                            RelativeAddress = rva,
                            FullAddress = (IntPtr)((long)moduleBaseAddr + rva)
                        });
                    }
                }

                for (int i = 0; i <= exportHeader.NumberOfNames - 1; i++)
                {
                    int ordinal = exportHeader.OrdinalBase + Marshal.ReadInt16(pNameOrdinals, i * 2);
                    ExportedFunction entry = listOfFunctions[ordinal];
                    IntPtr nameAddress = IntPtr.Add(moduleBaseAddr, Marshal.ReadInt32(pNames, i * 4));
                    entry.Name = Marshal.PtrToStringAnsi(nameAddress);
                    if (entry.Name == functionName)
                        return entry.FullAddress;
                }
            }
            return IntPtr.Zero;

        }
        public unsafe static IntPtr GetModuleBaseAddress(string name, Process process)
        {
            int nHandleInfoSize = (int)sizeof(ProcessBasicInformation);
            IntPtr ipHandlePointer = Marshal.AllocHGlobal((int)nHandleInfoSize);
            uint nLength = 0;

            NtStatus n = NtQueryInformationProcess(process.Handle, ProcessInformationClass.ProcessBasicInformation, ipHandlePointer, (uint)nHandleInfoSize, out nLength);

            if (n != NtStatus.STATUS_SUCCESS)
                return IntPtr.Zero;

            ProcessBasicInformation processBasicInformation = new ProcessBasicInformation();
            processBasicInformation = (ProcessBasicInformation)Marshal.PtrToStructure(ipHandlePointer, processBasicInformation.GetType());

            if (IntPtr.Size == 4)
            {
                PEB32 peb32 = new PEB32();
                peb32 = (PEB32)Marshal.PtrToStructure(processBasicInformation.PebBaseAddress, peb32.GetType());

                PebLdrData pebLdrData = (PebLdrData)Marshal.PtrToStructure(peb32.Ldr, typeof(PebLdrData));

                //dte->DllBase != null
                for (LdrDataTableEntry* dte = (LdrDataTableEntry*)pebLdrData.InLoadOrderModuleList.Flink; dte->DllBase != IntPtr.Zero; dte = (LdrDataTableEntry*)dte->InLoadOrderLinks.Flink)
                {
                    if (dte->BaseDllName.ToString().ToLower() == name)
                    {
                        return dte->DllBase;
                    }
                }
            }
            else
            {
                PEB64 peb64 = new PEB64();
                peb64 = (PEB64)Marshal.PtrToStructure(processBasicInformation.PebBaseAddress, peb64.GetType());

                PebLdrData pebLdrData = (PebLdrData)Marshal.PtrToStructure(peb64.Ldr, typeof(PebLdrData));

                for (LdrDataTableEntry* dte = (LdrDataTableEntry*)pebLdrData.InLoadOrderModuleList.Flink; dte->DllBase != IntPtr.Zero; dte = (LdrDataTableEntry*)dte->InLoadOrderLinks.Flink)
                {
                    if (dte->BaseDllName.ToString().ToLower() == name)
                    {
                        return dte->DllBase;
                    }
                }
            }
            return IntPtr.Zero;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate int MessageBoxW(IntPtr wHandle, byte[] lpText, byte[] lpCap, ulong uType);
        static void Main(string[] args)
        {
            IntPtr ptrBaseAddress = GetExportAddress("user32.dll", "MessageBoxW");

            MessageBoxW callMsg = (MessageBoxW)Marshal.GetDelegateForFunctionPointer(ptrBaseAddress, typeof(MessageBoxW));

            callMsg(IntPtr.Zero, Encoding.Unicode.GetBytes("HELLO"), Encoding.Unicode.GetBytes("Read from custom export"), 0x0);
        }
    }
}
