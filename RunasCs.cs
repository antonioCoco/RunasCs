using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;

public static class RunasCs
{
    private const string error_string = "{{{RunasCsException}}}";
    private const UInt16 SW_HIDE = 0;
    private const Int32 Startf_UseStdHandles = 0x00000100;
    private const int TokenType = 1; //primary token
    private const uint GENERIC_ALL = 0x10000000;
    private const int LOGON32_PROVIDER_DEFAULT = 0; 
    private const uint CREATE_NO_WINDOW = 0x08000000;
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

    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    
    [DllImport("Kernel32.dll", SetLastError=true)]
    private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);
    
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
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
    
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
        if (CreatePipe(out hReadPipe, out hWritePipe, sa, BUFFER_SIZE_PIPE))
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
        output += System.Text.Encoding.Default.GetString(buffer, 0, (int)dwBytesRead);
        return output;
    }
    
    public static string RunAs(string username, string password, string cmd, string domainName, uint processTimeout, int logonType, int createProcessFunction)
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
        
        if(processTimeout>0){
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
            
            //enable all privileges assigned to the token
            if(logonType != 3 && logonType != 8)
                EnableAllPrivileges(hTokenDuplicate);
                
            if(createProcessFunction == 0){
                success = CreateProcessAsUser(hTokenDuplicate, processPath, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, out processInfo);
                if(success == false)
                {
                    output += error_string + "\r\nCreateProcessAsUser failed with error code : " + Marshal.GetLastWin32Error();
                    return output;
                }
            }
            if(createProcessFunction == 1){
                success = CreateProcessWithTokenW(hTokenDuplicate, 0, processPath, commandLine, CREATE_NO_WINDOW, IntPtr.Zero, null, ref startupInfo, out processInfo);
                if(success == false)
                {
                    output += error_string + "\r\nCreateProcessWithTokenW failed with error code: " + Marshal.GetLastWin32Error();
                    return output;
                }
            }
            CloseHandle(hToken);
            CloseHandle(hTokenDuplicate);
        }
        if(processTimeout>0){
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
    private static extern bool LookupAccountName(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, System.Text.StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);        
    
    
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
        System.Text.StringBuilder referencedDomainName = new System.Text.StringBuilder();
        uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
        SID_NAME_USE sidUse;
        int err = NO_ERROR;
        
        if(domain != "")
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
            this.CleanupHandles(-1);
        }
        if (err == 0)
        {
            userSid = Marshal.AllocHGlobal((int)cbSid);
            Marshal.Copy(Sid, 0, userSid, (int)cbSid);
        }
        else{
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
        stationName=System.Text.Encoding.Default.GetString(stationNameBytes).Substring(0, (int)lengthNeeded-1);

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
    private static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, System.Text.StringBuilder lpName, ref int cchName );
        
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
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
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

RunasCs v1.1 - @splinter_code

RunasCs is an utility to run specific processes with different permissions than the user's current logon provides
using explicit credentials.
RunasCs has an automatic detection to determine the best create process function for every contexts.
Based on the caller token permissions, it will use one of the create process function in the following preferred order:
    1. CreateProcessAsUser();
    2. CreateProcessWithTokenW();
    3. CreateProcessWithLogonW().
The two processes (calling and called) will communicate through 1 file (both for stdout and stderr).
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
    domain                  domain of the user, if in a domain. 
                            Default: """"
    process_timeout         the waiting time (in ms) to use in 
                            the WaitForSingleObject() function.
                            This will halt the process until the spawned
                            process ends and sent the output back to the caller.
                            If you set 0 an async process will be
                            created and no output will be retrieved.
                            If this parameter is set to 0 it won't be
                            used cmd.exe to spawn the process.
                            Default: ""120000""
    logon_type              the logon type for the spawned process.
                            Default: ""3""

Examples:
    Run a command as a specific local user
        RunasCs.exe user1 password1 whoami
    Run a command as a specific domain user
        RunasCs.exe user1 password1 whoami domain
    Run a command as a specific local user with interactive logon type (2)
        RunasCs.exe user1 password1 whoami """" 120000 2
    Run a background/async process as a specific local user,
    i.e. meterpreter ps1 reverse shell
        RunasCs.exe ""user1"" ""password1"" ""%COMSPEC% powershell -enc..."" """" ""0""
    Run a background/async interactive process as a specific local user,
    i.e. meterpreter ps1 reverse shell
        RunasCs.exe ""user1"" ""password1"" ""%COMSPEC% powershell -enc.."" """" ""0"" ""2""

";
    
    private static bool HelpRequired(string param)
    {
        return param == "-h" || param == "--help" || param == "/?";
    }
    
    private static void CheckArgs(string[] arguments)
    {
        if(arguments.Length < 3){
            Console.Out.Write("RunasCs: Not enough arguments. 3 Arguments required. Use --help for additional help.\r\n");
            System.Environment.Exit(-1);
        }
            
    }
    
    private static void DisplayHelp()
    {
        Console.Out.Write(help);
    }

    private static string ParseDomain(string[] arguments){
        string domain = "";
        if (arguments.Length > 3)
            domain = arguments[3];
        return domain;
    }
    
    private static uint ParseProcessTimeout(string[] arguments){
        uint processTimeout = 120000;
        if (arguments.Length > 4){
            try{
                processTimeout = Convert.ToUInt32(arguments[4]);
            }
            catch{
                Console.Out.Write("RunasCs: Invalid process_timeout value: " + arguments[4].ToString());
                System.Environment.Exit(-1);
            }
        }
        return processTimeout;
    }
    
    private static int ParseLogonType(string[] arguments){
        int logonType = 3;
        if (arguments.Length > 5){
            try{
                logonType = Convert.ToInt32(arguments[5]);
            }
            catch{
                Console.Out.Write("RunasCs: Invalid logon_type value: " + arguments[5].ToString());
                System.Environment.Exit(-1);
            }
        }
        return logonType;
    }
    
    private static int ParseCreateProcessFunction(string[] arguments){
        //auto detect the create process function based on current privileges
        int createProcessFunction = 2;//default createProcessWithLogonW()
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
        //if a create process function is forced, use it. It should be just for debug.
        if (arguments.Length > 6)
            createProcessFunction = Convert.ToInt32(arguments[6]);
        return createProcessFunction;
    }
    
    public static string RunasCsMain(string[] args){
        string output="";
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            DisplayHelp();
        }
        else
        {
            CheckArgs(args);
            string username = args[0];
            string password = args[1];
            string cmd = args[2];
            string domain = ParseDomain(args);
            uint processTimeout = ParseProcessTimeout(args);
            int logonType = ParseLogonType(args);
            int createProcessFunction = ParseCreateProcessFunction(args);
            output=RunasCs.RunAs(username, password, cmd, domain, processTimeout, logonType, createProcessFunction);
        }
        return output;
    }
}

class MainClass{
    static void Main(string[] args)
    {
        Console.Out.Write(RunasCsMainClass.RunasCsMain(args));
    }
}