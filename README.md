# GIUDA
GET a TGS on behalf of another user without password

Scenario: you are Local Administrator and there is a logged User you want to Impersonate!
Goal: From Local Admin to Domain Admin with Kerberos TGS
Required: Local Administrator and a Domain Admin Logged (or Disconnected). In this guide the Domain Admin User is CALIPENDULA\fagiolo

1. ask to GIUDA for a shell as SYSTEM
2. GIUDA -runaslsass            or
3. GIUDA -runaspid:PID          (a NT AUTHORITY\SYSTEM's PID, enumerate by yourself) you need a PID running with SeTcpPrivilege, search well and try also WINLOGON's PID!
![image](https://github.com/foxlox/GIUDA/assets/28823598/a04903ea-de62-4f57-951f-655c45ab26e4)


4. ask to GIUDA to show ALL Logged User's LUID
5. GIUDA -askluids

![image](https://github.com/foxlox/GIUDA/assets/28823598/b39e3839-b499-4bbc-b011-ab638ddc2874)


6. take the LUID that you want to impersonate and ask GIUDA to get the msdsspn that you want
![image](https://github.com/foxlox/GIUDA/assets/28823598/d1ce1a96-a6fc-4588-ade8-1212d7140cfa)

7. use PSSession to log on the Domain Controller
![image](https://github.com/foxlox/GIUDA/assets/28823598/5bef5372-f49c-4591-886e-7712158538c6)


# Thanks
Thank you to ewan22, he does a very powerful set of Pascal Units for AD
