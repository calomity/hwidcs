using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace program
{
    class program
    {
        [Flags]
        private enum AllocationTypes : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Reset = 0x80000,
            LargePages = 0x20000000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000
        }

        [Flags]
        private enum MemoryProtections : uint
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuartModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [Flags]
        private enum FreeTypes : uint
        {
            Decommit = 0x4000,
            Release = 0x8000
        }

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        private unsafe delegate void CPUID0Delegate(byte* buffer);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
        private unsafe delegate void CPUID1Delegate(byte* buffer);

        private static unsafe byte[] CPUID0()
        {
            byte[] buffer = new byte[12];

            if (IntPtr.Size == 4)
            {
                IntPtr p = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new UIntPtr((uint)x86_CPUID0_INSNS.Length),
                    AllocationTypes.Commit | AllocationTypes.Reserve,
                    MemoryProtections.ExecuteReadWrite);
                try
                {
                    Marshal.Copy(x86_CPUID0_INSNS, 0, p, x86_CPUID0_INSNS.Length);

                    CPUID0Delegate del = (CPUID0Delegate)Marshal.GetDelegateForFunctionPointer(p, typeof(CPUID0Delegate));

                    fixed (byte* newBuffer = &buffer[0])
                    {
                        del(newBuffer);
                    }
                }
                finally
                {
                    NativeMethods.VirtualFree(p, 0, FreeTypes.Release);
                }
            }
            else if (IntPtr.Size == 8)
            {
                IntPtr p = NativeMethods.VirtualAlloc(
                    IntPtr.Zero,
                    new UIntPtr((uint)x64_CPUID0_INSNS.Length),
                    AllocationTypes.Commit | AllocationTypes.Reserve,
                    MemoryProtections.ExecuteReadWrite);
                try
                {
                    Marshal.Copy(x64_CPUID0_INSNS, 0, p, x64_CPUID0_INSNS.Length);

                    CPUID0Delegate del = (CPUID0Delegate)Marshal.GetDelegateForFunctionPointer(p, typeof(CPUID0Delegate));

                    fixed (byte* newBuffer = &buffer[0])
                    {
                        del(newBuffer);
                    }
                }
                finally
                {
                    NativeMethods.VirtualFree(p, 0, FreeTypes.Release);
                }
            }

            return buffer;
        }

        private static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr VirtualAlloc(
                IntPtr lpAddress,
                UIntPtr dwSize,
                AllocationTypes flAllocationType,
                MemoryProtections flProtect);

            [DllImport("kernel32")]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool VirtualFree(
                IntPtr lpAddress,
                uint dwSize,
                FreeTypes flFreeType);
        }

        #region ASM
        private static readonly byte[] x86_CPUID0_INSNS = new byte[]
            {
                0x53,                      // push   %ebx
                0x31, 0xc0,                // xor    %eax,%eax
                0x0f, 0xa2,                // cpuid
                0x8b, 0x44, 0x24, 0x08,    // mov    0x8(%esp),%eax
                0x89, 0x18,                // mov    %ebx,0x0(%eax)
                0x89, 0x50, 0x04,          // mov    %edx,0x4(%eax)
                0x89, 0x48, 0x08,          // mov    %ecx,0x8(%eax)
                0x5b,                      // pop    %ebx
                0xc3                       // ret
            };

        private static readonly byte[] x64_CPUID0_INSNS = new byte[]
            {
                0x49, 0x89, 0xd8,       // mov    %rbx,%r8
                0x49, 0x89, 0xc9,       // mov    %rcx,%r9
                0x48, 0x31, 0xc0,       // xor    %rax,%rax
                0x0f, 0xa2,             // cpuid
                0x4c, 0x89, 0xc8,       // mov    %r9,%rax
                0x89, 0x18,             // mov    %ebx,0x0(%rax)
                0x89, 0x50, 0x04,       // mov    %edx,0x4(%rax)
                0x89, 0x48, 0x08,       // mov    %ecx,0x8(%rax)
                0x4c, 0x89, 0xc3,       // mov    %r8,%rbx
                0xc3                    // retq
            };
        #endregion

        private const int CREATE_NEW = 1;
        private const int OPEN_EXISTING = 3;
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const int FILE_SHARE_READ = 0x1;
        private const int FILE_SHARE_WRITE = 0x2;
        private const int VER_PLATFORM_WIN32_NT = 2;
        private const int DFP_RECEIVE_DRIVE_DATA = 0x7C088;
        private const int INVALID_HANDLE_VALUE = -1;

        const int ProcessorInformation = 11;
        const uint STATUS_SUCCESS = 0;

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESSOR_POWER_INFORMATION
        {
            public uint Number;
            public uint MaxMhz;
            public uint CurrentMhz;
            public uint MhzLimit;
            public uint MaxIdleState;
            public uint CurrentIdleState;
        }

        [DllImport("powrprof.dll")]
        static extern uint CallNtPowerInformation(
            int InformationLevel,
            IntPtr lpInputBuffer,
            int nInputBufferSize,
            [Out] PROCESSOR_POWER_INFORMATION[] processorPowerInformation,
            int nOutputBufferSize
        );

        [StructLayout(LayoutKind.Sequential, Size = 8)]
        private class IDEREGS
        {
            public byte Features;
            public byte SectorCount;
            public byte SectorNumber;
            public byte CylinderLow;
            public byte CylinderHigh;
            public byte DriveHead;
            public byte Command;
            public byte Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Size = 32)]
        private class SENDCMDINPARAMS
        {
            public int BufferSize;
            public IDEREGS DriveRegs;
            public byte DriveNumber;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public int[] Reserved2;
            public SENDCMDINPARAMS()
            {
                DriveRegs = new IDEREGS();
                Reserved = new byte[3];
                Reserved2 = new int[4];
            }
        }
        [StructLayout(LayoutKind.Sequential, Size = 12)]
        private class DRIVERSTATUS
        {
            public byte DriveError;
            public byte IDEStatus;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public int[] Reserved2;
            public DRIVERSTATUS()
            {
                Reserved = new byte[2];
                Reserved2 = new int[2];
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private class IDSECTOR
        {
            public short GenConfig;
            public short NumberCylinders;
            public short Reserved;
            public short NumberHeads;
            public short BytesPerTrack;
            public short BytesPerSector;
            public short SectorsPerTrack;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public short[] VendorUnique;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public char[] SerialNumber;
            public short BufferClass;
            public short BufferSize;
            public short ECCSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] FirmwareRevision;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
            public char[] ModelNumber;
            public short MoreVendorUnique;
            public short DoubleWordIO;
            public short Capabilities;
            public short Reserved1;
            public short PIOTiming;
            public short DMATiming;
            public short BS;
            public short NumberCurrentCyls;
            public short NumberCurrentHeads;
            public short NumberCurrentSectorsPerTrack;
            public int CurrentSectorCapacity;
            public short MultipleSectorCapacity;
            public short MultipleSectorStuff;
            public int TotalAddressableSectors;
            public short SingleWordDMA;
            public short MultiWordDMA;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 382)]
            public byte[] Reserved2;
            public IDSECTOR()
            {
                VendorUnique = new short[3];
                Reserved2 = new byte[382];
                FirmwareRevision = new char[8];
                SerialNumber = new char[20];
                ModelNumber = new char[40];
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private class SENDCMDOUTPARAMS
        {
            public int BufferSize;
            public DRIVERSTATUS Status;
            public IDSECTOR IDS;
            public SENDCMDOUTPARAMS()
            {
                Status = new DRIVERSTATUS();
                IDS = new IDSECTOR();
            }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern int CloseHandle(int hObject);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern int CreateFile(
                    string lpFileName,
                    uint dwDesiredAccess,
                    int dwShareMode,
                    int lpSecurityAttributes,
                    int dwCreationDisposition,
                    int dwFlagsAndAttributes,
                    int hTemplateFile
                );

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern int DeviceIoControl(
                int hDevice,
                int dwIoControlCode,
                [In(), Out()] SENDCMDINPARAMS lpInBuffer,
                int lpInBufferSize,
                [In(), Out()] SENDCMDOUTPARAMS lpOutBuffer,
                int lpOutBufferSize,
                ref int lpBytesReturned,
                int lpOverlapped
            );

        [DllImport("kernel32.dll")]
        private static extern long GetVolumeInformation(
            string PathName,
            StringBuilder VolumeNameBuffer,
            UInt32 VolumeNameSize,
            ref UInt32 VolumeSerialNumber,
            ref UInt32 MaximumComponentLength,
            ref UInt32 FileSystemFlags,
            StringBuilder FileSystemNameBuffer,
            UInt32 FileSystemNameSize);

        [DllImport("user32.dll")]
        static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

        [Flags()]
        public enum DisplayDeviceStateFlags : int
        {
            AttachedToDesktop = 0x1,
            MultiDriver = 0x2,
            PrimaryDevice = 0x4,
            MirroringDriver = 0x8,
            VGACompatible = 0x10,
            Removable = 0x20,
            ModesPruned = 0x8000000,
            Remote = 0x4000000,
            Disconnect = 0x2000000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct DISPLAY_DEVICE
        {
            [MarshalAs(UnmanagedType.U4)]
            public int cb;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string DeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string DeviceString;
            [MarshalAs(UnmanagedType.U4)]
            public DisplayDeviceStateFlags StateFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string DeviceID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string DeviceKey;
        }
        [DllImport("iphlpapi.dll", CharSet = CharSet.Ansi)]
        public static extern int GetAdaptersInfo(IntPtr pAdapterInfo, ref Int64 pBufOutLen);
        const int MAX_ADAPTER_DESCRIPTION_LENGTH = 128;
        const int ERROR_BUFFER_OVERFLOW = 111;
        const int MAX_ADAPTER_NAME_LENGTH = 256;
        const int MAX_ADAPTER_ADDRESS_LENGTH = 8;
        const int MIB_IF_TYPE_OTHER = 1;
        const int MIB_IF_TYPE_ETHERNET = 6;
        const int MIB_IF_TYPE_TOKENRING = 9;
        const int MIB_IF_TYPE_FDDI = 15;
        const int MIB_IF_TYPE_PPP = 23;
        const int MIB_IF_TYPE_LOOPBACK = 24;
        const int MIB_IF_TYPE_SLIP = 28;
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IP_ADAPTER_INFO
        {
            public IntPtr Next;
            public Int32 ComboIndex;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ADAPTER_NAME_LENGTH + 4)]
            public string AdapterName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ADAPTER_DESCRIPTION_LENGTH + 4)]
            public string AdapterDescription;
            public UInt32 AddressLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_ADAPTER_ADDRESS_LENGTH)]
            public byte[] Address;
            public Int32 Index;
            public UInt32 Type;
            public UInt32 DhcpEnabled;
            public IntPtr CurrentIpAddress;
            public IP_ADDR_STRING IpAddressList;
            public IP_ADDR_STRING GatewayList;
            public IP_ADDR_STRING DhcpServer;
            public bool HaveWins;
            public IP_ADDR_STRING PrimaryWinsServer;
            public IP_ADDR_STRING SecondaryWinsServer;
            public Int32 LeaseObtained;
            public Int32 LeaseExpires;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IP_ADDR_STRING
        {
            public IntPtr Next;
            public IP_ADDRESS_STRING IpAddress;
            public IP_ADDRESS_STRING IpMask;
            public Int32 Context;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct IP_ADDRESS_STRING
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
            public string Address;
        }
        public static void Main(string[] args)
        {
            uint serialnumber = 0;
            uint lenght = 0;
            StringBuilder volumename = new StringBuilder(256);
            UInt32 file_system_flags = new UInt32();
            StringBuilder filesystemflag = new StringBuilder(256);
            if (GetVolumeInformation("C:\\", volumename, (UInt32)volumename.Capacity, ref serialnumber, ref lenght, ref file_system_flags, filesystemflag, (UInt32)filesystemflag.Capacity) == null)
            {
                Console.WriteLine("hata");
            }
            else
            {
                Console.WriteLine("C:\\ Volume Serial Number ");
                Console.WriteLine(serialnumber.ToString("X0"));
            }
            string serialNumber = " ";
            bool result;
            int handle, returnSize = 0;
            int driveNumber = 0;
            SENDCMDINPARAMS sci = new SENDCMDINPARAMS();
            SENDCMDOUTPARAMS sco = new SENDCMDOUTPARAMS();
            handle = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
            if (handle != INVALID_HANDLE_VALUE)
            {
                sci.DriveNumber = (byte)driveNumber;
                sci.BufferSize = Marshal.SizeOf(sco);
                sci.DriveRegs.DriveHead = (byte)(0xA0 | driveNumber << 4);
                sci.DriveRegs.Command = 0xEC;
                sci.DriveRegs.SectorCount = 1;
                sci.DriveRegs.SectorNumber = 1;
                if (DeviceIoControl(handle, DFP_RECEIVE_DRIVE_DATA, sci, Marshal.SizeOf(sci), sco, Marshal.SizeOf(sco), ref returnSize, 0) != 0)
                {
                    char[] harddriveserialnumber = sco.IDS.SerialNumber;
                    string s = new string(harddriveserialnumber);
                    Console.WriteLine("Hard Drive Serial Number ");
                    Console.WriteLine(s.TrimStart());
                }
                CloseHandle(handle);
            }
            else
            {
                Console.WriteLine("hata");
            }
            int procCount = Environment.ProcessorCount;
            PROCESSOR_POWER_INFORMATION[] procInfo =
                new PROCESSOR_POWER_INFORMATION[procCount];
            uint retval = CallNtPowerInformation(
                ProcessorInformation,
                IntPtr.Zero,
                0,
                procInfo,
                procInfo.Length * Marshal.SizeOf(typeof(PROCESSOR_POWER_INFORMATION))
            );
            if (retval == STATUS_SUCCESS)
            {
                foreach (var item in procInfo)
                {
                    //console.writeline(item.number); gibi
                    //buraya istediğini yazarsın
                }
            }
            DISPLAY_DEVICE d = new DISPLAY_DEVICE();
            d.cb = Marshal.SizeOf(d);
            try
            {
                for (uint id = 0; EnumDisplayDevices(null, id, ref d, 0); id++)
                {
                    Console.WriteLine(
                        String.Format("Device Name: {0}\n Device ID: {1}\n Device Key: {2}\n",
                                 d.DeviceName,
                                 d.DeviceID,
                                 d.DeviceKey
                                 )
                                  );
                    d.cb = Marshal.SizeOf(d);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("{0}", ex.ToString()));
            }
            long structSize = Marshal.SizeOf(typeof(IP_ADAPTER_INFO));
            IntPtr pArray = Marshal.AllocHGlobal(new IntPtr(structSize));

            int ret = GetAdaptersInfo(pArray, ref structSize);

            if (ret == ERROR_BUFFER_OVERFLOW)
            {
                pArray = Marshal.ReAllocHGlobal(pArray, new IntPtr(structSize));

                ret = GetAdaptersInfo(pArray, ref structSize);
            } 

            if (ret == 0)
            {
                IntPtr pEntry = pArray;

                do
                {
                    IP_ADAPTER_INFO entry = (IP_ADAPTER_INFO)Marshal.PtrToStructure(pEntry, typeof(IP_ADAPTER_INFO));
                    string tmpString = string.Empty;
                    Console.WriteLine("Desc: {0}", entry.AdapterDescription);
                    Console.WriteLine( "Name: {0}", entry.AdapterName );
                    Console.WriteLine("IP Address     : {0}", entry.IpAddressList.IpAddress.Address);
                    tmpString = string.Empty;
                    for (int i = 0; i < entry.Address.Length - 1; i++)
                    {
                        tmpString += string.Format("{0:X2}-", entry.Address[i]);
                    }
                    Console.WriteLine("MAC Address    : {0}{1:X2}\n", tmpString, entry.Address[entry.Address.Length - 1]);
                    pEntry = entry.Next;

                }
                while (pEntry != IntPtr.Zero);

                Marshal.FreeHGlobal(pArray);

            }
            else
            {
                Marshal.FreeHGlobal(pArray);
                throw new InvalidOperationException("GetAdaptersInfo failed: " + ret);
            }
            Console.WriteLine("CPUID0 ");
            Console.WriteLine(string.Join("", CPUID0().Select(x => x.ToString("X2", CultureInfo.InvariantCulture))));
        }
    }
}
