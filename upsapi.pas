unit upsapi;

{$mode delphi}


interface

uses
  Classes, SysUtils,windows,utils;

type phmodule=^hmodule;

  type
  LPMODULEINFO = ^MODULEINFO;
  {$EXTERNALSYM LPMODULEINFO}
  _MODULEINFO = record
    lpBaseOfDll: LPVOID;
    SizeOfImage: DWORD;
    EntryPoint: LPVOID;
  end;
  {$EXTERNALSYM _MODULEINFO}
  MODULEINFO = _MODULEINFO;
  {$EXTERNALSYM MODULEINFO}
  TModuleInfo = MODULEINFO;
  PModuleInfo = LPMODULEINFO;

  type
    PPROC_THREAD_ATTRIBUTE_LIST = Pointer;

    STARTUPINFOEXW = packed record
      StartupInfo: TStartupInfoW;
      lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST;
    end;

    type PSIZE_T=^SIZE_T;

    type
  _SYSTEM_INFORMATION_CLASS = (
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemNotImplemented1,
    SystemProcessesAndThreadsInformation,
    SystemCallCounts,
    SystemConfigurationInformation,
    SystemProcessorTimes,
    SystemGlobalFlag,
    SystemNotImplemented2,
    SystemModuleInformation,
    SystemLockInformation,
    SystemNotImplemented3,
    SystemNotImplemented4,
    SystemNotImplemented5,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPagefileInformation,
    SystemInstructionEmulationCounts,
    SystemInvalidInfoClass1,
    SystemCacheInformation,
    SystemPoolTagInformation,
    SystemProcessorStatistics,
    SystemDpcInformation,
    SystemNotImplemented6,
    SystemLoadImage,
    SystemUnloadImage,
    SystemTimeAdjustment,
    SystemNotImplemented7,
    SystemNotImplemented8,
    SystemNotImplemented9,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemLoadAndCallImage,
    SystemPrioritySeparation,
    SystemNotImplemented10,
    SystemNotImplemented11,
    SystemInvalidInfoClass2,
    SystemInvalidInfoClass3,
    SystemTimeZoneInformation,
    SystemLookasideInformation,
    SystemSetTimeSlipEvent,
    SystemCreateSession,
    SystemDeleteSession,
    SystemInvalidInfoClass4,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation);
  SYSTEM_INFORMATION_CLASS = _SYSTEM_INFORMATION_CLASS;

    type TUNICODE_STRING  = packed record
                      wLength       : ushort;
                      wMaximumLength: ushort;
                      {$ifdef CPU64}dummy:dword;{$endif cpu64}
                      Buffer       : PWideChar;
                    end;
UNICODE_STRING = TUNICODE_STRING;
PUNICODE_STRING = ^TUNICODE_STRING;

type KPRIORITY = Integer;

VM_COUNTERS = packed record
    PeakVirtualSize : ULONG;
    VirtualSize : ULONG;
    PageFaultCount : ULONG;
    PeakWorkingSetSize : ULONG;
    WorkingSetSize : ULONG;
    QuotaPeakPagedPoolUsage : ULONG;
    QuotaPagedPoolUsage : ULONG;
    QuotaPeakNonPagedPoolUsage : ULONG;
    QuotaNonPagedPoolUsage : ULONG;
    PageFileUsage : ULONG;
    PeakPageFileUsage : ULONG;
  end;

  IO_COUNTERS = packed record
    ReadOperationCount : LARGE_INTEGER;
    WriteOperationCount : LARGE_INTEGER;
    OtherOperationCount : LARGE_INTEGER;
    ReadTransferCount : LARGE_INTEGER;
    WriteTransferCount : LARGE_INTEGER;
    OtherTransferCount : LARGE_INTEGER;
  end;

  SClientID=record
       UniqueProcess:DWORD;
       UniqueThread:DWORD;
end;

  _SYSTEM_THREADS =record
        KernelTime:LARGE_INTEGER;
        UserTime:LARGE_INTEGER;
        CreateTime:LARGE_INTEGER;
        WaitTime:ULONG;
        StartAddress:pointer; //pvoid
        ClientId:SClientId;
        Priority:LongInt; //long
        BasePriority:LongInt;
        ContextSwitchCount:LongInt;
        State:LongInt;
        WaitReason:LongInt;
  end;

  //https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm

    type _SYSTEM_PROCESSES = record // Information Class 5
        NextEntryDelta: ULONG;
        ThreadCount: ULONG;
        Reserved1: array [0..5] of ULONG;

        {
        Reserved1:  nativeint; //LARGE_INTEGER;
        Reserved2:  ULONG;
        Reserved3:  ULONG;
        reserved4:  ULONGLONG;
        }

        CreateTime: nativeint; //LARGE_INTEGER;
        UserTime: nativeint; //LARGE_INTEGER;
        KernelTime: nativeint; //LARGE_INTEGER;
        ProcessName: UNICODE_STRING;
        BasePriority: nativeint; //long //KPRIORITY;
        ProcessId: ULONG;
        InheritedFromProcessId: ULONG;
        HandleCount: ULONG;
        SessionId: ULONG;
        Reservedx: ULONG;
        VmCounters: VM_COUNTERS;
        IoCounters: IO_COUNTERS;  // Windows 2000 only
        Threads: array [0..0] of _SYSTEM_THREADS;
      end;
      SYSTEM_PROCESSES = _SYSTEM_PROCESSES;
      PSYSTEM_PROCESSES = ^SYSTEM_PROCESSES;
      TSystemProcesses = SYSTEM_PROCESSES;
      PSystemProcesses = PSYSTEM_PROCESSES;

      Process = record // Information Class 5
    ProcessName: string;
    user:string;
    ProcessId: ULONG;
    InheritedFromProcessId: ULONG;
    SessionId: ULONG;
    threads:array of DWORD;
  end;

      {
      function NtQuerySystemInformation(SystemInformationClass: SYSTEM_INFORMATION_CLASS;
                                        SystemInformation: PVOID;
                                        SystemInformationLength: ULONG;
                                        ReturnLength: PULONG
                                        ): NTSTATUS; stdcall;external 'ntdll.dll';
      }

      {
function GetModuleInformation(hProcess: HANDLE; hModule: HMODULE;
  var lpmodinfo: MODULEINFO; cb: DWORD): BOOL; stdcall;external 'psapi.dll';

  function EnumProcessModules(hProcess: HANDLE; lphModule: PHMODULE; cb: DWORD;
    var lpcbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';

  function GetModuleFileNameExA(hProcess: HANDLE; hModule: HMODULE; lpFilename: LPSTR;
  nSize: DWORD): DWORD; stdcall;external 'psapi.dll';

  function EnumProcesses(lpidProcess: LPDWORD; cb: DWORD; var cbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';

  function GetModuleBaseNameA(hProcess: HANDLE; hModule: HMODULE; lpBaseName: LPSTR;
nSize: DWORD): DWORD; stdcall;external 'psapi.dll';
  }

  { WinVista API }
  //let go for late binding so that we can still run on xp
  {
  function InitializeProcThreadAttributeList(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST; dwAttributeCount, dwFlags: DWORD; var lpSize: Cardinal): Boolean; stdcall;
    external 'kernel32.dll';

  function UpdateProcThreadAttribute(
       lpAttributeList : PPROC_THREAD_ATTRIBUTE_LIST;   //__inout
       dwFlags : DWORD;                                 //__in
       Attribute : DWORD_PTR;                           //__in
       lpValue : pvoid;                                 //__in_bcount_opt(cbSize)
       cbSize : SIZE_T;                                 //__in
       lpPreviousValue : PVOID;                         //__out_bcount_opt(cbSize)
       lpReturnSize : PSIZE_T                           //__in_opt
      ) : BOOL; stdcall; external 'kernel32.dll';

  procedure DeleteProcThreadAttributeList(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST); stdcall; external 'Kernel32.dll';
  }

  //
  function _EnumProc2(search:string='';buser:boolean=false):dword;
  function _EnumProc(search:string=''):dword;
  function _EnumMod(pid:dword;search:string=''):thandle;
  function _killproc(pid:dword):boolean;
  function CreateProcessOnParentProcess(pid:dword;ExeName: string):boolean;

  var
    GetModuleInformation:function(hProcess: HANDLE; hModule: HMODULE;
  var lpmodinfo: MODULEINFO; cb: DWORD): BOOL; stdcall;

   EnumProcessModules:function(hProcess: HANDLE; lphModule: PHMODULE; cb: DWORD;
    var lpcbNeeded: DWORD): BOOL; stdcall;

   GetModuleFileNameExA:function(hProcess: HANDLE; hModule: HMODULE; lpFilename: LPSTR;
  nSize: DWORD): DWORD; stdcall;

   EnumProcesses:function(lpidProcess: LPDWORD; cb: DWORD; var cbNeeded: DWORD): BOOL; stdcall;

   GetModuleBaseNameA:function(hProcess: HANDLE; hModule: HMODULE; lpBaseName: LPSTR;
nSize: DWORD): DWORD; stdcall;

implementation

const
  SE_SECURITY_NAME                     = 'SeSecurityPrivilege';
  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = $00020000;
  EXTENDED_STARTUPINFO_PRESENT         = $00080000;

type
  PTOKEN_USER = ^TOKEN_USER;
  _TOKEN_USER = record
    User: TSidAndAttributes;
  end;
  TOKEN_USER = _TOKEN_USER;

  function GetProcessUserAndDomain(dwProcessID: DWORD;var UserName, Domain: AnsiString): Boolean;
    var
      hToken: THandle;
      cbBuf: Cardinal;
      tokUser: PTOKEN_USER;
      sidNameUse: SID_NAME_USE;
      hProcess: THandle;
      UserSize, DomainSize: DWORD;
      bSuccess: Boolean;
    begin
      Result := False;
      hProcess := OpenProcess(PROCESS_QUERY_INFORMATION, False, dwProcessID);
      if hProcess <> 0 then begin
        if OpenProcessToken(hProcess, TOKEN_QUERY, hToken) then begin
          bSuccess := GetTokenInformation(hToken, TokenUser, nil, 0, cbBuf);
          tokUser := nil;
          while (not bSuccess) and
              (GetLastError = ERROR_INSUFFICIENT_BUFFER) do begin
            ReallocMem(tokUser, cbBuf);
            bSuccess := GetTokenInformation(hToken, TokenUser, tokUser, cbBuf, cbBuf);
          end;// while (not bSuccess) and...
          FileClose(hToken); { *Converti depuis CloseHandle* }
          if not bSuccess then
            Exit;
          UserSize := 0;
          DomainSize := 0;
          LookupAccountSid(nil, tokUser.User.Sid, nil, UserSize, nil, DomainSize, sidNameUse);
          if (UserSize <> 0) and (DomainSize <> 0) then begin
            SetLength(UserName, UserSize);
            SetLength(Domain, DomainSize);
            if LookupAccountSid(nil, tokUser.User.Sid, PAnsiChar(UserName), UserSize,
                PAnsiChar(Domain), DomainSize, sidNameUse) then begin
              Result := True;
              UserName := StrPas(PAnsiChar(UserName));
              Domain := StrPas(PAnsiChar(Domain));
            end;// if LookupAccountSid(nil, tokUser.User.Sid, PAnsiChar(UserName), UserSize,
          end;// if (UserSize <> 0) and (DomainSize <> 0) then begin
          if bSuccess then
            FreeMem(tokUser);
        end;// if OpenProcessToken(hProcess, TOKEN_QUERY, hToken) then begin
        FileClose(hProcess); { *Converti depuis CloseHandle* }
      end;// if hProcess <> 0 then begin
    end;// function TDGProcessList.GetProcessUserAndDomain(dwProcessID: DWORD;

function _killproc(pid:dword):boolean;
var
  hProcess:thandle=thandle(-1);
begin
  result:=false;
       HProcess := OpenProcess(PROCESS_TERMINATE, False, pid);
           if HProcess <> thandle(-1) then
           begin
             Result := TerminateProcess(HProcess, 0);
             if result=false then log('terminateprocess:'+inttostr(getlasterror));
             CloseHandle(HProcess);
           end
           else log('invalid handle');
end;

function _EnumMod(pid:dword;search:string=''):thandle;
var
  cbneeded:dword;
  count:dword;
  modules:array[0..1023] of thandle;
  hProcess:thandle=thandle(-1);
  szModName:array[0..259] of char;
begin
result:=0;
hProcess:=thandle(-1);
//beware of 32bit process onto 64bits processes...
hProcess := OpenProcess( PROCESS_QUERY_INFORMATION or
                         PROCESS_VM_READ,
                         FALSE, pid );

 if hProcess<>thandle(-1) then
 begin
   if EnumProcessModules (hProcess,@modules[0],SizeOf(hmodule)*1024,cbneeded) then
      begin
      //writeln(cbneeded div sizeof(dword)); //debug
      for count:=0 to cbneeded div sizeof(thandle) - 1 do
          begin

          //EnumProcessModules (hprocess,@modules[0],cb,cbneeded2);
          if GetModuleBaseNameA( hProcess, modules[count], szModName,sizeof(szModName))<>0 then
             begin
             if search='' then writeln(inttohex(modules[count],sizeof(thandle))+ ' '+szModName );
             if lowercase(search)=lowercase(strpas(szModName) ) then
                begin
                result:=modules[count];
                break;
                end; //if lowercase...
             end;// if GetModuleBaseNameA...
             //else writeln(getlasterror);
          end; //for count:=0...
      end//if EnumProcesses...
      else log('EnumProcessModules failed:'+inttostr(getlasterror),0);
   closehandle(hProcess);
 end
 else log('OpenProcess failed',0);
end;

//uses NtQuerySystemInformation which does not need to openprocess with PROCESS_QUERY_INFORMATION or PROCESS_VM_READ
//therefore, less likely to be blocked by AV's
function _EnumProc2(search:string='';buser:boolean=false):dword;
var
 i,rl,cp : dword;
 pinfo : PSystemProcesses;
 buf : Pointer;
 dim: dword;
 username,domain,tmp:string;
 t:_SYSTEM_THREADS ;
 //
 processes:array of process;
 //
 NtQuerySystemInformation:function (SystemInformationClass: SYSTEM_INFORMATION_CLASS;
                                        SystemInformation: PVOID;
                                        SystemInformationLength: ULONG;
                                        ReturnLength: PULONG
                                        ): NTSTATUS; stdcall;
begin
   {$ifdef CPU32}result:=_enumproc(search);exit;{$endif cpu32}
   //
   NtQuerySystemInformation:=getProcAddress(loadlibrary('ntdll.dll'),'NtQuerySystemInformation');
   //
   result:=0;
   log('**** _EnumProc2 ****');
  dim := 256*1024;
  GetMem(buf, dim);
  rl := 0;
  //messageboxa(0,'test1','',0);
  i := NtQuerySystemInformation(SystemProcessesAndThreadsInformation, buf, dim, @rl);
  while (i = $C0000004) do
    begin
      dim := dim + (256*1024);
      FreeMem(buf);
      GetMem(buf, dim);
      i := NtQuerySystemInformation(SystemProcessesAndThreadsInformation, buf, dim, @rl);
    end;
  if i = 0 then
    begin
      cp := 0;
      setlength(processes,0);

      repeat
        pinfo := PSystemProcesses(Pointer(nativeuint(buf) + cp));
        if pinfo=nil then break;
        cp := cp + pinfo.NextEntryDelta;
        //setlength(processes,length(processes)+1);
        with pinfo^ do
          begin
          if search='' then
          begin
          if buser then
          if GetProcessUserAndDomain (ProcessId,username,domain)=true
                   then tmp:=domain+'\'+username
                   else tmp:='';
          //log(WideCharToString(ProcessName.Buffer)+#9+tmp,1 );
          log(inttostr(ProcessId)+ #9+WideCharToString(ProcessName.Buffer)+#9+tmp,1 );
          end; //if search='' then
          if search<>'' then
          if lowercase(search)=lowercase(strpas(ProcessName.Buffer) ) then
             begin
             result:=ProcessId;
             break;
             end; //if lowercase...
          //threads
          {
          SetLength(processes[length(processes)-1].threads,pinfo^.ThreadCount);
          for i:=0 to pinfo^.ThreadCount -1 do
            begin
            CopyMemory(@t,pointer(dword(@pinfo^.Threads[0])+(sizeof(t)*i)),sizeof(t));
            processes[length(processes)-1].threads[i]:=t.ClientId.UniqueThread;
            end;
          //
          }
          {
            if (ProcessName.Buffer <> nil)
              then processes[length(processes)-1].ProcessName :=WideCharToString(ProcessName.Buffer)
              else processes[length(processes)-1].ProcessName:='System Idle';
            processes[length(processes)-1].user:=(' ');
            if buser then if GetProcessUserAndDomain(ProcessId,user,domain)
              then processes[length(processes)-1].user:= user;
            //li.SubItems.Add(IntToStr(ThreadCount));
            processes[length(processes)-1].ProcessId :=ProcessId;
            processes[length(processes)-1].InheritedFromProcessId :=InheritedFromProcessId;
            //li.SubItems.Add(IntToStr(HandleCount));
            processes[length(processes)-1].SessionId :=SessionId;
           }
            //

          end; //with
      until (pinfo.NextEntryDelta = 0);
    end;
 FreeMem(buf);
end;

function _EnumProc(search:string=''):dword;
var
  cb,cbneeded,cbneeded2:dword;
  count:dword;
  pids,modules:array[0..1023] of dword;
  hProcess:thandle;
  szProcessName:array[0..259] of char;
  username,domain,tmp:string;
begin
result:=0;
   cb:=sizeof(dword)*1024;
   if EnumProcesses (@pids[0],cb,cbneeded) then
      begin
      //writeln(cbneeded div sizeof(dword)); //debug
      for count:=0 to cbneeded div sizeof(dword) - 1 do
          begin
          //beware of 32bit process onto 64bits processes...
          hProcess := OpenProcess( PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
                                   FALSE, pids[count] );
          if hprocess<=0 then log( inttostr(pids[count])+', OpenProcess failed - '+inttostr(getlasterror));
          if hprocess>0 then
          if GetModuleBaseNameA( hProcess, 0, szProcessName,sizeof(szProcessName))<>0 then
             begin
             if search='' then
                begin
                if GetProcessUserAndDomain (pids[count],username,domain)=true
                   then tmp:=domain+'\'+username
                   else tmp:='';
                log(inttostr(pids[count])+ #9+szProcessName+#9+tmp,1 );
                end; //if search='' then
             if lowercase(search)=lowercase(strpas(szProcessName) ) then
                begin
                result:=pids[count];
                break;
                end; //if lowercase...
             end// if GetModuleBaseNameA...
             else log( inttostr(pids[count])+', GetModuleBaseNameA failed - '+inttostr(getlasterror));
             closehandle(hProcess);
          end; //for count:=0...
      end//if EnumProcesses...
      else log('EnumProcesses failed, '+inttostr(getlasterror));
end;

function EnableDebugPrivilege(PrivName: string; CanDebug: Boolean): Boolean;
var
  TP,prev    : Windows.TOKEN_PRIVILEGES;
  Dummy : Cardinal;
  hToken: THandle;
begin
  htoken:=0;
  //OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES, hToken);
  OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, hToken);
  TP.PrivilegeCount := 1;
  LookupPrivilegeValue(nil, pchar(PrivName), TP.Privileges[0].Luid);
  if CanDebug then
    TP.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
  else
    TP.Privileges[0].Attributes := 0;
  Result                        := AdjustTokenPrivileges(hToken, False, TP, SizeOf(TP), prev, Dummy);
  hToken                        := 0;
end;

function CreateProcessOnParentProcess(pid:dword;ExeName: string):boolean;
type
TInitializeProcThreadAttributeList=function(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST; dwAttributeCount, dwFlags: DWORD; var lpSize: Cardinal): Boolean; stdcall;
TUpdateProcThreadAttribute=function(
    lpAttributeList : PPROC_THREAD_ATTRIBUTE_LIST;
    dwFlags : DWORD;
    Attribute : DWORD_PTR;
    lpValue : pvoid;
    cbSize : SIZE_T;
    lpPreviousValue : PVOID;
    lpReturnSize : PSIZE_T
    ) : BOOL; stdcall;
TDeleteProcThreadAttributeList=procedure(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST); stdcall;
var
  pi         : TProcessInformation;
  si         : STARTUPINFOEXW;
  cbAListSize: Cardinal;
  pAList     : PPROC_THREAD_ATTRIBUTE_LIST;
  hParent    : thandle;
  exitcode:dword;
  ptr:pointer;
  ts,ps:SECURITY_ATTRIBUTES ;
begin
  //writeln(pid);
  result:=false;
  {
  if EnableDebugPrivilege(SE_SECURITY_NAME, True)=false
     then writeln('EnableDebugPrivilege NOT OK');
  }


  FillChar(si, SizeOf(si), 0);
  si.StartupInfo.cb          := SizeOf(si);
  si.StartupInfo.dwFlags     := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
  si.StartupInfo.wShowWindow := SW_SHOWDEFAULT;
  //si.STARTUPINFO.lpDesktop   :='WinSta0\Default';
  //si.StartupInfo.lpDesktop :='';
  FillChar(pi, SizeOf(pi), 0);

  cbAListSize := 0;
  ptr:=GetProcAddress (loadlibrary('kernel32.dll'),'InitializeProcThreadAttributeList');
  //InitializeProcThreadAttributeList(nil, 1, 0, cbAListSize);
  TInitializeProcThreadAttributeList(ptr)(nil, 1, 0, cbAListSize);
  pAList := HeapAlloc(GetProcessHeap(), 0, cbAListSize);
  //if InitializeProcThreadAttributeList(pAList, 1, 0, cbAListSize)=false
  if TInitializeProcThreadAttributeList(ptr)(pAList, 1, 0, cbAListSize)=false
      then begin writeln('InitializeProcThreadAttributeList NOT OK');exit;end;
  hParent := OpenProcess({PROCESS_ALL_ACCESS}PROCESS_CREATE_PROCESS or PROCESS_DUP_HANDLE , False, pid);
  if hparent<=0 then begin writeln('OpenProcess NOT OK');exit;end;
  ptr:=GetProcAddress (loadlibrary('kernel32.dll'),'UpdateProcThreadAttribute');
  //if UpdateProcThreadAttribute(pAList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, @hParent, sizeof(thandle), nil, nil)=false
  if tUpdateProcThreadAttribute(ptr)(pAList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, @hParent, sizeof(thandle), nil, nil)=false
     then begin writeln('UpdateProcThreadAttribute NOT OK');exit;end;
  si.lpAttributeList := pAList;

  //need current dir?
  //need env?
  {
  ZeroMemory(@ts,sizeof(SECURITY_ATTRIBUTES ));
  ZeroMemory(@ps,sizeof(SECURITY_ATTRIBUTES ));
  ts.nLength :=sizeof(SECURITY_ATTRIBUTES );
  ps.nLength :=sizeof(SECURITY_ATTRIBUTES );
  }
  //CREATE_NEW_CONSOLE is needed or else console proggies like cmd will fail with a c0000142
  //note that we could start it suspended and modify the PEB
  //https://gist.github.com/xpn/1c51c2bfe19d33c169fe0431770f3020#file-argument_spoofing-cpp
  if CreateProcessW(PWideChar(widestring(ExeName)), nil, nil, nil, false, CREATE_NEW_CONSOLE or EXTENDED_STARTUPINFO_PRESENT,
  nil, {pwidechar(widestring(ExtractFilepath  (ExeName)))}nil, si.StartupInfo  , pi) then
  begin
    //if GetExitCodeProcess (pi.hProcess ,exitcode) then writeln(exitcode);
    //WaitForInputIdle(pi.hprocess,5000);
    //sleep(15000);
    writeln('pid:'+inttostr(pi.dwProcessId));
    //CloseHandle(pi.hProcess);
    //CloseHandle(pi.hThread);
    result:=true;
  end
  else writeln('error:'+inttostr(getlasterror));
  ptr:=GetProcAddress (loadlibrary('kernel32.dll'),'DeleteProcThreadAttributeList');
  //DeleteProcThreadAttributeList(pAList);
  TDeleteProcThreadAttributeList(ptr)(pAList);
  HeapFree(GetProcessHeap(), 0, pAList);
  closehandle(hparent);
end;

function initAPI:boolean;
  var lib:hmodule=0;
  begin
  //writeln('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('psapi.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('psapi.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary ntdll.dll');
    exit;
    end;
      GetModuleInformation:=getProcAddress(lib,'GetModuleInformation');
      EnumProcessModules:=getProcAddress(lib,'EnumProcessModules');
      GetModuleFileNameExA:=getProcAddress(lib,'GetModuleFileNameExA');
      EnumProcesses:=getProcAddress(lib,'EnumProcesses');
      GetModuleBaseNameA:=getProcAddress(lib,'GetModuleBaseNameA');

  result:=true;
  except
  //on e:exception do writeln('init error:'+e.message);
     writeln('init error');
  end;
  //log('init:'+BoolToStr (result,'true','false'));
  end;

initialization
initAPI ;

end.

