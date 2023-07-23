unit usecur32;

{$mode delphi}


interface

uses
  Classes, SysUtils,windows,utils,lsaapi;

  procedure GetActiveUserNames(func:pointer=nil);
  function GetActiveUserNamesArray(func:pointer=nil):string;

  type
    _LUID = record
    LowPart: DWORD;
    HighPart: LongInt;
  end;
  PLuid = ^_LUID;
  LUID = _LUID;

    _LSA_UNICODE_STRING = record
    Length: USHORT;  //2
    MaximumLength:  USHORT;   //2
    {$ifdef CPU64}dummy:dword;{$endif cpu64} //alignon 8 bytes
    Buffer: LPWSTR;          //are we aligned ok there?
  end;
  LSA_UNICODE_STRING = _LSA_UNICODE_STRING;

      //{$PackRecords 8}
      PLSA_STRING=^LSA_STRING;
      _LSA_STRING = record
        Length: USHORT;
        MaximumLength: USHORT;
        {$ifdef CPU64}dummy:dword;{$endif cpu64}
        Buffer: PCHAR;
        //{$PackRecords default}
      end;
      LSA_STRING = _LSA_STRING;

    _SECURITY_LOGON_TYPE = (
    seltFiller0, seltFiller1,
    Interactive,
    Network,
    Batch,
    Service,
    Proxy,
    Unlock,
    NetworkCleartext,
    NewCredentials,
    RemoteInteractive,
    CachedInteractive,
    CachedRemoteInteractive);
  SECURITY_LOGON_TYPE = _SECURITY_LOGON_TYPE;

  //https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data
   PSECURITY_LOGON_SESSION_DATA = ^SECURITY_LOGON_SESSION_DATA;
  _SECURITY_LOGON_SESSION_DATA = record
    Size: ULONG;
    LogonId: _LUID;
    UserName: LSA_UNICODE_STRING;
    LogonDomain: LSA_UNICODE_STRING;
    AuthenticationPackage: LSA_UNICODE_STRING;
    LogonType: SECURITY_LOGON_TYPE;
    Session: ULONG;
    Sid: PSID;
    LogonTime: LARGE_INTEGER;
    LogonServer: LSA_UNICODE_STRING;
    DnsDomainName: LSA_UNICODE_STRING;
    Upn: LSA_UNICODE_STRING;
    //there is more...
  end;
  SECURITY_LOGON_SESSION_DATA = _SECURITY_LOGON_SESSION_DATA;

  PPVOID = ^PVOID;
  PNTSTATUS = ^NTSTATUS;

var
   //https://docs.microsoft.com/en-usSTATUS_UNSUCCESSFUL/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage
 LsaCallAuthenticationPackage:function(
        LsaHandle:handle;       //[in]  HANDLE
        AuthenticationPackage:ulong;  //[in]  ULONG
        ProtocolSubmitBuffer:PVOID;    //[in]  PVOID
        SubmitBufferLength:ulong;       //[in]  ULONG
        ProtocolReturnBuffer:ppvoid;         //[out] PVOID
        ReturnBufferLength:pulong;         //[out] PULONG
        ProtocolStatus:PNTSTATUS             //[out] PNTSTATUS
 ):NTSTATUS;stdcall;

  LsaConnectUntrusted:function( LsaHandle:PHANDLE):NTSTATUS ;stdcall;

  LsaLookupAuthenticationPackage:function(
       LsaHandle:HANDLE;
       PackageName:PLSA_STRING;
       AuthenticationPackage:PULONG
 ):NTSTATUS ;stdcall;

 LsaRegisterLogonProcess:function(
     LogonProcessName:PLSA_STRING;
     LsaHandle:PHANDLE;
     SecurityMode:PLSA_OPERATIONAL_MODE
  ):NTSTATUS;stdcall;

  LsaDeregisterLogonProcess:function(LsaHandle:HANDLE):NTSTATUS;stdcall;

  LsaFreeReturnBuffer:function (buffer : pointer) : NTSTATUS; stdcall;

implementation

type
  PTOKEN_USER = ^TOKEN_USER;
  _TOKEN_USER = record
    User: TSidAndAttributes;
  end;
  TOKEN_USER = _TOKEN_USER;

  USHORT = word;

  const
  apilib = 'secur32.dll';


var
 lib: THandle = 0;
  //
  //LsaFreeReturnBuffer:function(Buffer: pointer): Integer; stdcall;
  LsaEnumerateLogonSessions:function(Count: PULONG; List: PLUID): LongInt; stdcall;
  LsaGetLogonSessionData:function(LogonId: PLUID;var ppLogonSessionData: PSECURITY_LOGON_SESSION_DATA): LongInt; stdcall;

  function InitAPI: Boolean;
begin
  Result := False;
  if Win32Platform <> VER_PLATFORM_WIN32_NT then Exit;
  if lib = 0 then lib := LoadLibrary(apilib);
  if lib > HINSTANCE_ERROR then
  begin
    LsaFreeReturnBuffer := GetProcAddress(lib, 'LsaFreeReturnBuffer');
    LsaEnumerateLogonSessions := GetProcAddress(lib, 'LsaEnumerateLogonSessions');
    LsaGetLogonSessionData := GetProcAddress(lib, 'LsaGetLogonSessionData');
    //
    LsaCallAuthenticationPackage:=getProcAddress(lib,'LsaCallAuthenticationPackage');
    LsaConnectUntrusted:=getProcAddress(lib,'LsaConnectUntrusted');
    LsaLookupAuthenticationPackage:=getProcAddress(lib,'LsaLookupAuthenticationPackage');
    LsaRegisterLogonProcess:=getProcAddress(lib,'LsaRegisterLogonProcess');
    LsaDeregisterLogonProcess:=getProcAddress(lib,'LsaDeregisterLogonProcess');
    //LsaFreeReturnBuffer:=getProcAddress(lib,'LsaFreeReturnBuffer');
    Result := True;
  end;
end;

procedure FreeAPI;
begin
  if lib <> 0 then FreeLibrary(lib);
  lib := 0;
end;

function FileTimeToDateTime(const FileTime: Int64): TDateTime; // Change the Filetime type to Int64 as FileTime is passed to me Int64 already

const
FileTimeBase      = -109205.0;
FileTimeStep: Extended = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0 * 10.0; // 100 nSek per Day
begin
Result := (FileTime) / FileTimeStep; // Remove the Int64 conversion as FileTime arrives as Int64 already
Result := Result + FileTimeBase;
end;


(*fox*)
function GetActiveUserNamesArray(func:pointer=nil):string;
var
   Count: cardinal;
   List: PLUID;
   kk:integer=0;
   sessionData: PSECURITY_LOGON_SESSION_DATA;
   i1: integer;
   SizeNeeded, SizeNeeded2: DWORD;
   OwnerName, DomainName: PChar;
   OwnerType: SID_NAME_USE;
   //pBuffer: Pointer;
   //pBytesreturned: DWord;
   sUser,toreturn : string;
   LocalFileTime: TFileTime;
   LogonTime:tdatetime;
begin
   //result:= '';
   //Listing LogOnSessions
   i1:= lsaNtStatusToWinError(LsaEnumerateLogonSessions(@Count, @List));
   try
      if i1 = 0 then
      begin
          i1:= -1;
          if Count > 0 then
          begin
              //log('user'#9'authpackage'#9'logonserver'#9'logonid'#9'session'#9'logontime',1);
              repeat
                inc(i1);
                LsaGetLogonSessionData(List, sessionData);
                //Checks if it is an interactive session
                sUser := sessionData.UserName.Buffer;
                {if (sessionData.LogonType = Interactive)
                  or (sessionData.LogonType = RemoteInteractive)
                  or (sessionData.LogonType = CachedInteractive)
                  or (sessionData.LogonType = CachedRemoteInteractive) then}

                if sessionData.LogonType<>network then
                begin
                    //
                    SizeNeeded := MAX_PATH;
                    SizeNeeded2:= MAX_PATH;
                    GetMem(OwnerName, MAX_PATH);
                    GetMem(DomainName, MAX_PATH);
                    try
                    if LookupAccountSID(nil, sessionData.SID, OwnerName,
                                       SizeNeeded, DomainName,SizeNeeded2,
                                       OwnerType) then
                    begin
                      if integer(OwnerType) = 1 then  //This is a USER account SID (SidTypeUser=1)
                      begin
                        sUser := AnsiUpperCase(sessionData.LogonDomain.Buffer);
                        sUser := sUser + '\';
                        sUser := sUser + AnsiUpperCase(sessionData.UserName.Buffer);
                        if FileTimeToLocalFileTime(TFileTime(sessionData.LogonTime),LocalFileTime)
                          then LogonTime:=FileTimeToDateTime(LARGE_INTEGER(LocalFileTime).QuadPart );

                        if sessionData.AuthenticationPackage.Buffer <> 'NTLM' then
                         begin

                          writeln(kk);
                          writeln(suser+#9#9+sessionData.AuthenticationPackage.Buffer+#9#9+inttohex(LARGE_INTEGER(sessionData.LogonId).QuadPart,8)+#9);
                          toreturn:=toreturn+sUser+':'+inttohex(LARGE_INTEGER(sessionData.LogonId).QuadPart,8)+',';
                          inc(kk);
                         end;
                        if func<>nil then fn(func)(sessionData);
                       end;
                    end;
                    finally
                    FreeMem(OwnerName);
                    FreeMem(DomainName);
                    end;
                end;
                inc(List);
                try
                    LSAFreeReturnBuffer(sessionData);
                except
                end;
            until (i1 = Count-1);// or (result <> '');
          end;
      end;
   finally
      LSAFreeReturnBuffer(List);
      result:=toreturn;
   end;
end;

procedure GetActiveUserNames(func:pointer=nil);
var
   Count: cardinal;
   List: PLUID;
   sessionData: PSECURITY_LOGON_SESSION_DATA;
   i1: integer;
   SizeNeeded, SizeNeeded2: DWORD;
   OwnerName, DomainName: PChar;
   OwnerType: SID_NAME_USE;
   //pBuffer: Pointer;
   //pBytesreturned: DWord;
   sUser : string;
   LocalFileTime: TFileTime;
   LogonTime:tdatetime;
begin
   //result:= '';
   //Listing LogOnSessions
   i1:= lsaNtStatusToWinError(LsaEnumerateLogonSessions(@Count, @List));
   try
      if i1 = 0 then
      begin
          i1:= -1;
          if Count > 0 then
          begin
              //log('user'#9'authpackage'#9'logonserver'#9'logonid'#9'session'#9'logontime',1);
              repeat
                inc(i1);
                LsaGetLogonSessionData(List, sessionData);
                //Checks if it is an interactive session
                sUser := sessionData.UserName.Buffer;
                {if (sessionData.LogonType = Interactive)
                  or (sessionData.LogonType = RemoteInteractive)
                  or (sessionData.LogonType = CachedInteractive)
                  or (sessionData.LogonType = CachedRemoteInteractive) then}
                if sessionData.LogonType<>network then
                begin
                    //
                    SizeNeeded := MAX_PATH;
                    SizeNeeded2:= MAX_PATH;
                    GetMem(OwnerName, MAX_PATH);
                    GetMem(DomainName, MAX_PATH);
                    try
                    if LookupAccountSID(nil, sessionData.SID, OwnerName,
                                       SizeNeeded, DomainName,SizeNeeded2,
                                       OwnerType) then
                    begin
                      if integer(OwnerType) = 1 then  //This is a USER account SID (SidTypeUser=1)
                      begin
                        sUser := AnsiUpperCase(sessionData.LogonDomain.Buffer);
                        sUser := sUser + '\';
                        sUser := sUser + AnsiUpperCase(sessionData.UserName.Buffer);
                        if FileTimeToLocalFileTime(TFileTime(sessionData.LogonTime),LocalFileTime)
                          then LogonTime:=FileTimeToDateTime(LARGE_INTEGER(LocalFileTime).QuadPart );
                        if sessionData.AuthenticationPackage.Buffer <> 'NTLM' then writeln(suser+#9#9
                            +sessionData.AuthenticationPackage.Buffer+#9#9
                            +inttohex(LARGE_INTEGER(sessionData.LogonId).QuadPart,8)+#9);
                        if func<>nil then fn(func)(sessionData);
                       end;
                    end;
                    finally
                    FreeMem(OwnerName);
                    FreeMem(DomainName);
                    end;
                end;
                inc(List);
                try
                    LSAFreeReturnBuffer(sessionData);
                except
                end;
            until (i1 = Count-1);// or (result <> '');
          end;
      end;
   finally
      LSAFreeReturnBuffer(List);
   end;
end;

initialization InitAPI;
finalization FreeAPI;

end.

