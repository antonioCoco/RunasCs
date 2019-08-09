using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions;
using System.Security.AccessControl;
using System.Collections.Generic;

public static class RunasCs
{
    private const string error_string = "{{{RunasCsException}}}";
    private const UInt16 SW_HIDE = 0;
    private const Int32 Startf_UseStdHandles = 0x00000100;
    private const Int32 StdOutputHandle = -11;
    private const Int32 StdErrorHandle = -12;
    private const int TokenType = 1; //primary token
    private const uint GENERIC_ALL = 0x10000000;
    private const int LOGON32_PROVIDER_DEFAULT = 0; 
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    
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
    
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
    private struct StartupInfo
    {
        public int    cb;
        public String reserved;
        public String desktop;
        public String title;
        public int    x;
        public int    y;
        public int    xSize;
        public int    ySize;
        public int    xCountChars;
        public int    yCountChars;
        public int    fillAttribute;
        public int    flags;
        public UInt16 showWindow;
        public UInt16 reserved2;
        public byte   reserved3;
        public IntPtr stdInput;
        public IntPtr stdOutput;
        public IntPtr stdError;
    }

    private struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int    processId;
        public int    threadId;
    }
    
    [StructLayout(LayoutKind.Sequential)] private struct SECURITY_ATTRIBUTES
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
    private static extern bool CreateProcessWithLogonW(String userName,String domain,String password,UInt32 logonFlags,String applicationName,String commandLine,uint creationFlags,UInt32 environment,String currentDirectory,ref   StartupInfo startupInfo,out  ProcessInformation processInformation);
    
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool CreateProcessAsUser(IntPtr hToken,string lpApplicationName,string lpCommandLine,ref SECURITY_ATTRIBUTES lpProcessAttributes,ref SECURITY_ATTRIBUTES lpThreadAttributes,bool bInheritHandles,uint dwCreationFlags,IntPtr lpEnvironment,string lpCurrentDirectory,ref StartupInfo lpStartupInfo,out ProcessInformation lpProcessInformation);  

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref StartupInfo lpStartupInfo, out ProcessInformation lpProcessInformation);
    
    //https://stackoverflow.com/questions/1344221/how-can-i-generate-random-alphanumeric-strings
    private static string GenRandomString(int length)
    {
        string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        char[] stringChars = new char[length];
        Random random = new Random();
        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }
        string finalString = new String(stringChars);
        return finalString;
    }
    
    private static void GrantEveryoneAccess(string fullPath)
    {
        DirectoryInfo dInfo = new DirectoryInfo(fullPath);
        DirectorySecurity dSecurity = dInfo.GetAccessControl();
        dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
        dInfo.SetAccessControl(dSecurity);
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
    
    [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]
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
        StartupInfo startupInfo = new StartupInfo();
        startupInfo.reserved = null;
        startupInfo.flags &= Startf_UseStdHandles;
        //startupInfo.showWindow = SW_HIDE;
        startupInfo.stdOutput = (IntPtr)StdOutputHandle;
        startupInfo.stdError = (IntPtr)StdErrorHandle;
        ProcessInformation processInfo = new ProcessInformation();
        String currentDirectory = System.IO.Directory.GetCurrentDirectory();
        string outfile = Environment.GetEnvironmentVariable("TEMP") + "\\" + GenRandomString(5); 
        String commandLine = "";
        if(processTimeout>0){
            cmd = cmd.Replace("\"", "\"\"");
            File.Create(outfile).Dispose();
            GrantEveryoneAccess(outfile);
            commandLine = Environment.GetEnvironmentVariable("ComSpec") + " /c \"" + cmd + "\" >> " + outfile + " 2>&1";
        }
        else{
            commandLine = cmd;
        }
        if(createProcessFunction == 2){
            success = CreateProcessWithLogonW(username, domainName, password, (UInt32) 1, null, commandLine, CREATE_NO_WINDOW, (UInt32) 0, currentDirectory, ref startupInfo, out processInfo);
            if (success == false){
                output += error_string + "\r\nCreateProcessWithLogonW failed with " + Marshal.GetLastWin32Error();
                return output;
            }
        }
        else{
            startupInfo.desktop = "Winsta0\\default";
            IntPtr hToken = new IntPtr(0);
            IntPtr hTokenDuplicate = new IntPtr(0);
            success = LogonUser(username, domainName, password, logonType, LOGON32_PROVIDER_DEFAULT, ref hToken);
            if(success == false)
            {
                output += error_string + "\r\nWrong Credentials. LogonUser failed with error code : " + Marshal.GetLastWin32Error();
                return output;
            }
            SECURITY_ATTRIBUTES sa  = new SECURITY_ATTRIBUTES();
            sa.bInheritHandle       = false;
            sa.Length               = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = (IntPtr)0;
            success = DuplicateTokenEx(hToken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TokenType, ref hTokenDuplicate);
            if(success == false)
            {
                output += error_string + "\r\nDuplicateTokenEx failed with error code : " + Marshal.GetLastWin32Error();
                return output;
            }
            
            //enable all privileges assigned to the token
            if(logonType != 3 && logonType != 8)
                EnableAllPrivileges(hTokenDuplicate);
                
            if(createProcessFunction == 0){
                success = CreateProcessAsUser(hTokenDuplicate,null, commandLine, ref sa, ref sa, false, CREATE_NO_WINDOW, (IntPtr)0, currentDirectory, ref startupInfo, out processInfo);
                if(success == false)
                {
                    output += error_string + "\r\nCreateProcessAsUser failed with error code : " + Marshal.GetLastWin32Error();
                    return output;
                }
            }
            if(createProcessFunction == 1){
                success = CreateProcessWithTokenW(hTokenDuplicate, 0, null, commandLine, CREATE_NO_WINDOW, (IntPtr)0, currentDirectory, ref startupInfo, out processInfo);
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
            WaitForSingleObject(processInfo.process, processTimeout);
            output += File.ReadAllText(outfile);
            File.Delete(outfile);
        }
        else
            output += "\r\nAsync process with pid " + processInfo.processId + " created and left in background.\r\n";
        CloseHandle(processInfo.process);
        CloseHandle(processInfo.thread);        
        return output;
    }
    
}

public static class Token{
        
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
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
            System.Environment.Exit(0);
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
                System.Environment.Exit(0);
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
            System.Environment.Exit(0);
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
                System.Environment.Exit(0);
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
                System.Environment.Exit(0);
            }
        }
        return logonType;
    }
    
    private static int ParseCreateProcessFunction(string[] arguments){
        //auto detect the create process function based on current privileges
        int createProcessFunction = 2;//default createProcessWithLogonW()
        IntPtr currentTokenHandle = WindowsIdentity.GetCurrent().Token;        
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