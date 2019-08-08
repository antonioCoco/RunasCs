# RunasCs
<p>RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials.</p>
<p>This tool is an improved (from a pentest perspective) and open version of windows builtin runas.exe that solves some limitations:</p>
<ul>
  <li> Allows explicit credentials;</li>
  <li>Works both if spawned from interactive process and from service process;</li>
  <li>Uses more reliable and free create process functions like CreateProcessAsUser() and CreateProcessWithTokenW() if the calling process holds the required privileges (automatic detection);</li>
  <li>Allows to specify the logon type, i.e. network logon 3 (no UAC limitations);</li>
  <li>It's Open Source :)</li>
</ul>
<br>
<p>RunasCs has an automatic detection to determine the best create process function for every contexts.
Based on the process caller token permissions, it will use one of the create process function in the following preferred order:
    <ol>
      <li> CreateProcessAsUser();</li>
      <li> CreateProcessWithTokenW();</li>
      <li> CreateProcessWithLogonW().</li>
    </ol>
</p>

## Requirements
<p>.NET Framework >= 2.0</p>

## Usage
```
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
                            Default: ""
    process_timeout         the waiting time (in ms) to use in
                            the WaitForSingleObject() function.
                            This will halt the process until the spawned
                            process ends and sent the output back to the caller.
                            If you set 0 an async process will be
                            created and no output will be retrieved.
                            If this parameter is set to 0 it won't be
                            used cmd.exe to spawn the process.
                            Default: "120000"
    logon_type              the logon type for the spawned process.
                            Default: "3"

Examples:
    Run a command as a specific local user
        RunasCs.exe user1 password1 whoami
    Run a command as a specific domain user
        RunasCs.exe user1 password1 whoami domain
    Run a command as a specific local user with interactive logon type (2)
        RunasCs.exe user1 password1 whoami "" 120000 2
    Run a background/async process as a specific local user,
    i.e. meterpreter ps1 reverse shell
        RunasCs.exe "user1" "password1" "%COMSPEC% powershell -enc..." "" "0"
    Run a background/async interactive process as a specific local user,
    i.e. meterpreter ps1 reverse shell
        RunasCs.exe "user1" "password1" "%COMSPEC% powershell -enc.." "" "0" "2"
```

## References
https://decoder.cloud/2018/01/13/potato-and-tokens/

## Credits
<a href="https://github.com/decoder-it">@decoder</a>
