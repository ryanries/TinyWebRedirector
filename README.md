# TinyWebRedirector
Simply listens for and redirects HTTP requests.

```
TinyWebRedirector v1.0 - Redirects HTTP Requests
Copyright (C) 2015 Joseph Ryan Ries
www.myotherpcisacloud.com

Usage:
Install:   TinyWebRedirector -install
Uninstall: TinyWebRedirector -uninstall
```

I wrote this micro web server for all the sysadmins out there who have an internal Active Directory that shares
the same DNS name as their public domain name. Let's say your internal AD domain name is contoso.com. Your public website is
also contoso.com. In this scenario, internal employees cannot reach your public website by entering http://contoso.com 
into their web browsers, because contoso.com internally resolves to the IP address of one of your AD domain controllers.
This has lead to messy solutions, such as installing IIS on each domain controller, for the sole purpose of redirecting
requests on port 80 to <b>www.</b>contoso.com. But installing IIS on your domain controllers is not a great idea.

TinyWebRedirector is more suited to this purpose because:

- It is tiny. The image file is 110KB, and runs with a ~2.6MB working set.
- It does one thing and one thing only. This translates to a much smaller potential attack surface than a large web server such as IIS.
- It is written in C, and so does not require .NET. Will run on any Windows machine Vista/2008 or greater.
- The listening port (default 80) and the URL to redirect visitors to is configurable in the registry at 
HKLM\SYSTEM\CurrentControlSet\Services\TinyWebRedirector. Restart the service for changes to take effect.
- The service runs as Local Service. This is a much safer configuration than services that run as Local System.

Please let me know if you find any bugs or weaknesses.

https://myotherpcisacloud.com
