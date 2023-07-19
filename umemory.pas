unit umemory;

{$mode delphi}

interface

uses
   SysUtils,windows,utils,upsapi,ntdll,jwanative;

function WriteMem(hprocess:thandle;offset:nativeint;bytes:array of byte):boolean;overload;
function WriteMem(hprocess:thandle;offset:nativeint;bytes:pointer;len:PtrUInt):boolean;overload;

function ReadMem(hprocess:thandle;offset:nativeuint;var bytes:array of byte):boolean;overload;
function ReadMem(hprocess:thandle;offset:nativeuint;bytes:pointer;len:PtrUInt):boolean;overload;

function SearchMem(hprocess:thandle;addr:pointer;sizeofimage:DWORD;pattern:array of byte):nativeint;
function SearchMem2(hprocess:thandle;addr:pointer;sizeofimage:DWORD;pattern:array of byte):nativeint;
function search_module_mem(pid:dword;module:string;pattern:tbytes;var found:nativeuint):boolean;

var
  WriteProcessMemory_:function(hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: PTRUINT; lpNumberOfBytesWritten: PPTRUINT): BOOL; //external 'kernel32' name 'WriteProcessMemory';
  ReadProcessMemory_:function(hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: PTRUINT;  lpNumberOfBytesRead: PPTRUINT): BOOL; //external 'kernel32' name 'ReadProcessMemory';

implementation

//type tbytes=array of byte;

function WriteMem(hprocess:thandle;offset:nativeint;bytes:pointer;len:PtrUInt):boolean;overload;
var
  written:PtrUInt; //cardinal;
  status:ntstatus=0;
  oldprotect:ulong=0;
begin
log('WriteMem offset:'+inttohex(offset,sizeof(offset))+' len:'+inttostr(len));
result:=WriteProcessMemory_ (hprocess,pointer(offset),bytes,len,@written);
//if NtProtectVirtualMemory(hprocess,ppvoid(offset),@len,PAGE_READWRITE,@oldprotect)=STATUS_SUCCESS then
   begin
   //status:=NtWriteVirtualMemory(hprocess,pointer(offset),bytes,len,@written);  //works
   //NtProtectVirtualMemory(hprocess,ppvoid(offset),@len,oldprotect,nil);
   end;
if status<>0 then
  begin
  result:=false;
  //log('status:'+inttohex(status,sizeof(status)));
  SetLastError (status);
  end
  else result:=true;
if written=0 then result:=false;
if result=false then log('WriteMem: written:'+inttostr(written)+' error:'+inttostr(getlasterror));
//ideally should check written against length(bytes) as well...
end;


function WriteMem(hprocess:thandle;offset:nativeint;bytes:array of byte):boolean;
var
  written:PtrUInt=0; //cardinal;
  status:ntstatus=0;
  oldprotect:ulong=0;
  len:ptruint=0;
begin
result:=writemem(hprocess,offset,@bytes[0],length(bytes));
exit;
len:=length(bytes);
log('WriteMem offset:'+inttohex(offset,sizeof(offset))+' len:'+inttostr(len));
result:=WriteProcessMemory_ (hprocess,pointer(offset),@bytes[0],len,@written);
//if NtProtectVirtualMemory(hprocess,ppvoid(offset),@len,PAGE_READWRITE,@oldprotect)=STATUS_SUCCESS  then
begin
  //status:=NtWriteVirtualMemory(hprocess,pointer(offset),@bytes[0],length(bytes),@written ); //works
  //NtProtectVirtualMemory(hprocess,ppvoid(offset),@len,oldprotect,nil);
  end;
//and finally?
//NtFlushInstructionCache
if status<>0 then
  begin
  result:=false;
  //log('status:'+inttohex(status,sizeof(status)));
  SetLastError (status);
  end
  else result:=true;
if written=0 then result:=false;
if result=false then log('WriteMem: written:'+inttostr(written)+' error:'+inttostr(getlasterror));
//ideally should check written against length(bytes) as well...
end;

function ReadMem(hprocess:thandle;offset:nativeuint;var bytes:array of byte):boolean;
var
  read:PtrUInt;
  status:ntstatus=0;
begin
result:=ReadMem(hprocess,offset,@bytes[0],length(bytes));
exit;
//
result:=false;
fillchar(bytes,length(bytes),0);
log('ReadMem offset:'+inttohex(offset,sizeof(offset))+' len:'+inttostr(length(bytes)));
//result:=ReadProcessMemory_ (hprocess,pointer(offset),@bytes[0],length(bytes),@read);
status:=NtReadVirtualMemory(hprocess,pointer(offset),@bytes[0],length(bytes),@read); //works
if status<>0 then
  begin
  result:=false;
  //log('status:'+inttohex(status,sizeof(status)));
  SetLastError (status);
  end
  else result:=true;
if read=0 then result:=false;
if result=false then log('readmem: read:'+inttostr(read)+' error:'+inttostr(getlasterror));
//ideally should check read against length(bytes) as well...
end;

function ReadMem(hprocess:thandle;offset:nativeuint;bytes:pointer;len:PtrUInt):boolean;overload;
var
  read:PtrUInt;
  status:ntstatus=0;
  //STATUS_ACCESS_DENIED = cardinal($C0000022);
begin
result:=false;
fillchar(bytes^,len,0);
log('ReadMem offset:'+inttohex(offset,sizeof(offset))+' len:'+inttostr(len));
//result:=ReadProcessMemory_ (hprocess,pointer(offset),bytes,len,@read);
status:=NtReadVirtualMemory(hprocess,pointer(offset),bytes,len,@read);  //works
if status<>0 then
  begin
  result:=false;
  //log('status:'+inttohex(status,sizeof(status)));
  SetLastError (status);
  end
  else result:=true;
if read=0 then result:=false;
if result=false then log('readmem: read:'+inttostr(read)+' error:'+inttostr(getlasterror));
//ideally should check read against length(bytes) as well...
end;

//https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L971
//pattern should be a parameter to make this function generic...
function SearchMem(hprocess:thandle;addr:pointer;sizeofimage:DWORD;pattern:array of byte):nativeint;
var
  i:nativeint;
  buffer:array of byte;
  //read:cardinal;
  read:PtrUInt;
begin
result:=0;
setlength(buffer,length(pattern));
zeromemory(@buffer[0],length(buffer));
//log(ByteToHexaString (@buffer[0],length(buffer)));
log('Searching...',0);
//log('Pattern:'+ByteToHexaString (@pattern[0],length(pattern)));
log('start:'+inttohex(nativeint(addr),sizeof(addr)));
log('sizeofimage:'+inttostr(sizeofimage));
  for i:=nativeint(addr) to nativeint(addr)+sizeofimage-length(buffer) do
      begin
      //fillchar(buffer,4,0);
      //read:=0;
      //if readmem(hprocess,i,@buffer[0],length(buffer)) then
      if ReadProcessMemory_( hprocess,pointer(i),@buffer[0],length(buffer),@read) then
        begin
        //log(inttohex(i,sizeof(pointer)));
        //log('read:'+inttostr(read));
        if CompareMem (@pattern [0],@buffer[0],length(buffer)) then
           begin
           //log(ByteToHexaString (@pattern[0],read));
           //log('found:'+ByteToHexaString (@buffer[0],length(buffer)));
           result:=i;
           //log('found:'+inttohex(i,sizeof(i)));
           break;
           end;
        end;//if readprocessmemory...
      end;//for
//log('Done!',0);
end;

function SearchMem2(hprocess:thandle;addr:pointer;sizeofimage:DWORD;pattern:array of byte):nativeint;
var
  i:nativeint;
  buffer:array of byte;
  //read:cardinal;
  read:PtrUInt;
  mem:pointer=nil;
begin
result:=0;
setlength(buffer,length(pattern));
zeromemory(@buffer[0],length(buffer));
//log(ByteToHexaString (@buffer[0],length(buffer)));
log('Searching...',0);
//log('Pattern:'+ByteToHexaString (@pattern[0],length(pattern)));
log('start:'+inttohex(nativeint(addr),sizeof(addr)));
log('sizeofimage:'+inttostr(sizeofimage));
mem:=AllocMem (sizeofimage);
if not ReadProcessMemory_( hprocess,addr,mem,sizeofimage ,@read) then
  begin
  log('ReadProcessMemory_ failed,'+inttostr(getlasterror));
  freemem(mem);
  exit;
  end;

for i:=0 to (sizeofimage-1) -length(buffer) do
      begin
        //log(inttohex(i,sizeof(pointer)));
        //log('read:'+inttostr(read));
        if CompareMem (@pattern [0],pointer(nativeint(mem)+i),length(buffer)) then
           begin
           //log(ByteToHexaString (@pattern[0],read));
           //log('found:'+ByteToHexaString (@buffer[0],length(buffer)));
           result:=nativeint(addr)+i;
           //log('found:'+inttohex(i,sizeof(i)));
           break;
           end; //if CompareMem...
      end;//for
//log('Done!',0);
freemem(mem);
end;

function search_module_mem(pid:dword;module:string;pattern:tbytes;var found:nativeuint):boolean;

var
  dummy:string;
  hprocess:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  offset:nativeint=0;
begin
log('**** search_module_mem ****');
result:=false;
  if pid=0 then exit;
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ {or PROCESS_VM_WRITE or PROCESS_VM_OPERATION} or PROCESS_QUERY_INFORMATION,
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);
       //log(inttohex(GetModuleHandle (nil),sizeof(nativeint)));
       cbneeded:=0;
       if EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded) then
               begin
               log('EnumProcessModules OK',0);

               for count:=0 to cbneeded div sizeof(thandle) do
                   begin
                    if GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) )>0 then
                      begin
                      dummy:=lowercase(strpas(szModName ));
                      if pos(lowercase(module),dummy)>0 then
                         begin
                         log(module+' found:'+inttohex(hMods[count],8),0);
                         if GetModuleInformation (hprocess,hMods[count],MODINFO ,sizeof(MODULEINFO)) then
                            begin
                            log('lpBaseOfDll:'+inttohex(nativeint(MODINFO.lpBaseOfDll),sizeof(pointer)),0 );
                            log('SizeOfImage:'+inttostr(MODINFO.SizeOfImage),0);


                            if found<>0 then
                               begin
                               log('relative offset:'+inttohex(found,sizeof(found)));
                               offset:=nativeint(MODINFO.lpBaseOfDll)+found;
                               log('virtual relative offset:'+inttohex(offset,sizeof(offset)));
                               end;


                            if found=0 then offset:=searchmem(hprocess,MODINFO.lpBaseOfDll,MODINFO.SizeOfImage,pattern);

                            log('Done!',0);
                            if offset<>0 then
                                 begin
                                 log('found :'+inttohex(offset,sizeof(pointer)),0);
                                 found:=offset;
                                 result:=true;
                                 end; //if offset<>0 then
                            end;//if GetModuleInformation...
                         break; //no need to go thru the whole list - only one module if of interest
                         end; //if pos(lowercase(module),dummy)>0 then
                      end; //if GetModuleFileNameExA
                   end; //for count:=0...
               end; //if EnumProcessModules...
       closehandle(hprocess);
       end;//if openprocess...
  log('**** search_module_mem: '+booltostr(result)+' ****');
end;

function initAPI:boolean;
  var lib:hmodule=0;
  begin
  //writeln('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('kernel32.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('kernel32.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary ntdll.dll');
    exit;
    end;
  WriteProcessMemory_:=getProcAddress(lib,'WriteProcessMemory');
  ReadProcessMemory_:=getProcAddress(lib,'ReadProcessMemory');

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

