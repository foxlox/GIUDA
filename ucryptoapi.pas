unit ucryptoapi;

{$ifdef fpc}{$mode delphi}{$endif fpc}

interface



uses
  windows,Classes, SysUtils,JwaWinCrypt,jwawintype,jwabcrypt,utils{$ifndef fpc},math{$endif fpc};

//light version...
type tmasterkey=record
  szGuid:tguid;
  //dwMasterKeyLen:dword;
  salt:array [0..15] of byte;
  rounds:dword;
  algHash:dword;
  algCrypt:dword;
  pbKey:array of byte;
  end;
  pmasterkey=^tmasterkey;

  type tDPAPI_CREDHIST_HEADER =record
  	dwVersion:DWORD;
  	guid_:GUID;
  	dwNextLen:DWORD;
  end;

  type tDPAPI_CREDHIST_ENTRY=record
    	header:tDPAPI_CREDHIST_HEADER;
	dwType:DWORD; // flags ?
	algHash:ALG_ID;
	rounds:DWORD;
	sidLen:DWORD;
	algCrypt:ALG_ID;
	sha1Len:DWORD;
	md4Len:DWORD;
	salt:array[0..15] of byte;
	pSid:PSID;
        stringsid:string;
	pSecret:array of byte; //PBYTE;
	__dwSecretLen:DWORD;
  end;
    pDPAPI_CREDHIST_ENTRY=^tDPAPI_CREDHIST_ENTRY;

    type tDPAPI_CREDHIST =record
    	 current:tDPAPI_CREDHIST_HEADER;
    	 entries:array of tDPAPI_CREDHIST_ENTRY;//array[0..0] of tDPAPI_CREDHIST_ENTRY;
    	 __dwCount:DWORD;
    end;
      pDPAPI_CREDHIST=^tDPAPI_CREDHIST;

type tdpapi_blob=record
  	dwVersion:DWORD;
	guidProvider:tguid;
	dwMasterKeyVersion:DWORD;
	guidMasterKey:tGUID;
	dwFlags:DWORD;
        dwDescriptionLen:DWORD;
        szDescription:LPWSTR;  //PWSTR
 	algCrypt:ALG_ID;
        dwAlgCryptLen:DWORD;
        dwSaltLen:DWORD;
        pbSalt:array of byte; //PBYTE
        dwHmacKeyLen:DWORD;
        pbHmackKey:PBYTE;
        algHash:ALG_ID;
        dwAlgHashLen:DWORD;
        dwHmac2KeyLen:DWORD;
        pbHmack2Key:array of byte; //PBYTE
        dwDataLen:DWORD;
        pbData:array of byte; //PBYTE;
        dwSignLen:DWORD;
        pbSign:array of byte; //PBYTE
  end;
  pdpapi_blob=^tdpapi_blob;

  type _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =record
         cbSize:ULONG;
         dwInfoVersion:ULONG;
         pbNonce:PBYTE; //PUCHAR;
         cbNonce:ULONG;
         pbAuthData:PBYTE; //PUCHAR;
         cbAuthData:ULONG;
         pbTag:PBYTE; //PUCHAR;
         cbTag:ULONG;
         pbMacContext:PBYTE; //PUCHAR;
         cbMacContext:ULONG;
         cbAAD:ULONG;
         cbData:ULONGLONG;
         dwFlags:ULONG;
  end;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO=_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
    PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO=^BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;


function DecryptAES128(const Key: tbyte16;const IV:array of byte;const data: tbyte16;var output:tbyte16): boolean;

function EnCryptDecrypt(algid:dword;hashid:dword;CRYPT_MODE:dword;const key: tbytes;var buffer:tbytes;const decrypt:boolean=false):boolean;

//function bdecrypt(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
function bdecrypt(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte;CHAINING_MODE:widestring=''):ULONG;
function bdecrypt_gcm(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
function bencrypt(algo:lpcwstr;decrypted:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;

function CryptProtectData_(dataBytes:array of byte;var output:tbytes;flags:dword=0):boolean;overload;
function CryptProtectData_(dataBytes:array of byte;filename:string;flags:dword=0):boolean;overload;

function CryptUnProtectData_(filename:string;var dataBytes:tbytes;const AdditionalEntropy: string=''):boolean;overload;
function CryptUnProtectData_(buffer:tbytes;var output:tbytes;const AdditionalEntropy: string=''):boolean;overload;

function decodecredblob(cred:pointer):boolean;
function decodecred(cred:pointer):boolean;
//function decodeblob(filename:string;var blob:tdpapi_blob):boolean;overload;
function decodeblob(filename:string;blob:pdpapi_blob;debug:byte=1):boolean;overload;
function decodeblob(buffer:tbytes; blob:pdpapi_blob;debug:byte=1):boolean;overload;
function decodemk(filename:string; mk:pmasterkey):boolean;
function decodecredhist(filename:string; credhist:pDPAPI_CREDHIST):boolean;

function crypto_hash_len( hashId:ALG_ID):dword;
function crypto_cipher_blocklen( hashId:ALG_ID):DWORD;
function crypto_cipher_keylen( hashId:ALG_ID):dword;

function crypto_hash_(algid:alg_id;data:LPCVOID;dataLen:DWORD; var output:tbytes;hashWanted:DWORD):boolean;
function crypto_hash(algid:alg_id;data:LPCVOID;dataLen:DWORD;  hash:lpvoid;hashWanted:DWORD):boolean;

function crypto_hash_hmac(calgid:DWORD; key:lpbyte;keyLen:DWORD; message:lpbyte; messageLen:DWORD; hash:LPVOID;hashWanted:DWORD ):boolean;

//function lsadump_sec_aes256(var hardSecretBlob:tbytes; hardSecretBlobSize:dword;lsaKeysStream:pointer;sysKey:tbyte16):boolean;
function lsadump_sec_aes256(var hardSecretBlob:tbytes; hardSecretBlobSize:dword;lsaKeysStream:pointer;sysKey:pointer):boolean;

//function CryptSetHashParam_(hHash: HCRYPTHASH; dwParam: DWORD; const pbData: LPBYTE;  dwFlags: DWORD): BOOL; stdcall;external 'Advapi32.dll' name 'CryptSetHashParam';

type
 PCREDENTIAL_ATTRIBUTEW = ^_CREDENTIAL_ATTRIBUTEW;
  _CREDENTIAL_ATTRIBUTEW = record
    Keyword: LPWSTR;
    Flags: DWORD;
    ValueSize: DWORD;
    Value: LPBYTE;
  end;


  PCREDENTIALW = ^_CREDENTIALW;
  _CREDENTIALW = record
    Flags: DWORD;
    Type_: DWORD;
    TargetName: LPWSTR;
    Comment: LPWSTR;
    LastWritten: FILETIME;
    CredentialBlobSize: DWORD;
    dummy : dword;
    CredentialBlob: LPBYTE;
    Persist: DWORD;
    AttributeCount: DWORD;
    Attributes: PCREDENTIAL_ATTRIBUTEW;
    TargetAlias: LPWSTR;
    UserName: LPWSTR;
  end;

PCredentialArray = array of PCREDENTIALW;

type CRED_BLOB =record
	credFlags:DWORD;
	credSize:DWORD;
	credUnk0:DWORD;

	Type_:DWORD;
	Flags:DWORD;
	LastWritten:windows.FILETIME;
	unkFlagsOrSize:DWORD;
	Persist:DWORD;
	AttributeCount:DWORD;
	unk0:DWORD;
	unk1:DWORD;
        data:array[0..0] of byte;
        {
	dwTargetName:DWORD;
	TargetName:array of byte; //LPWSTR;

	dwTargetAlias:DWORD;
	TargetAlias:array of byte; //LPWSTR;

	dwComment:DWORD;
	Comment:array of byte; //LPWSTR;

	dwUnkData:DWORD;
	UnkData:array of byte; //LPWSTR;

	dwUserName:DWORD;
	UserName:array of byte; //LPWSTR;

	CredentialBlobSize:DWORD;
	CredentialBlob:array of byte; //LPBYTE;

	Attributes:pointer ; //PKULL_M_CRED_ATTRIBUTE
        }
end;
  PCRED_BLOB=^CRED_BLOB;

//https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
const
  //cipher
  CALG_RC2 =    $00006602;
  CALG_RC4=	$00006801;
  CALG_RC5=     $0000660d;
  CALG_DES=	$00006601;
  CALG_DESX=	$00006604;
  CALG_3DES=	$00006603;
  CALG_3DES_112 = $00006609;
  CALG_AES=	$00006611;
  CALG_AES_128=	$0000660e;
  CALG_AES_192=	$0000660f;
  CALG_AES_256=	$00006610;
  //hash
  CALG_SHA1                 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA1;
  //CALG_HMAC=	$00008009;
  //CALG_MAC=	$00008005;

const
SHA_DIGEST_LENGTH=20;
LM_NTLM_HASH_LENGTH=16;

const
PROV_RSA_AES = 24;

type _PUBLICKEYSTRUC = record
           bType:BYTE;
           bVersion:BYTE;
           reserved:WORD;
           aiKeyAlg:ALG_ID;
end;
BLOBHEADER=_PUBLICKEYSTRUC;
PBLOBHEADER=^_PUBLICKEYSTRUC;
PUBLICKEYSTRUC=_PUBLICKEYSTRUC;

type _NT6_SYSTEM_KEY =record
	 KeyId:tGUID;
	 KeyType:DWORD;
	 KeySize:DWORD;
	 Key:array [0..0] of byte;
end;
  PNT6_SYSTEM_KEY=^_NT6_SYSTEM_KEY;

type _NT6_SYSTEM_KEYS =record
	unkType0:DWORD;
	CurrentKeyID:GUID;
	unkType1:DWORD;
	nbKeys:DWORD;
	Keys:array [0..0] of _NT6_SYSTEM_KEY;
end;
  PNT6_SYSTEM_KEYS=^_NT6_SYSTEM_KEYS;

type _NT6_CLEAR_SECRET =record
	SecretSize:DWORD;
	unk0:DWORD;
	unk1:DWORD;
	unk2:DWORD;
	Secret:array[0..0] of byte;
        end;
NT6_CLEAR_SECRET=_NT6_CLEAR_SECRET;
PNT6_CLEAR_SECRET=^NT6_CLEAR_SECRET;

//#define LAZY_NT6_IV_SIZE	32
//#define ANYSIZE_ARRAY 1
type _NT6_HARD_SECRET =record
	version:DWORD;
	KeyId:GUID;
	algorithm:DWORD;
	flag:DWORD;
	lazyiv:array [0..32-1] of byte;
	Secret:array [0..0] of byte; //can be encrypted or clear
        end;
 NT6_HARD_SECRET=_NT6_HARD_SECRET;
 PNT6_HARD_SECRET=^NT6_HARD_SECRET;

 //late binding rather than early binding as in jwawincrypt
 //late binding rather than early binding as in jwaBCcrypt
 var
  CryptProtectData:function(pDataIn: PDATA_BLOB; szDataDescr: LPCWSTR;
  pOptionalEntropy: PDATA_BLOB; pvReserved: PVOID;
  pPromptStruct: PCRYPTPROTECT_PROMPTSTRUCT; dwFlags: DWORD; pDataOut: PDATA_BLOB): BOOL; stdcall;


 CryptUnprotectData:function(pDataIn: PDATA_BLOB; ppszDataDescr: LPLPWSTR;
  pOptionalEntropy: PDATA_BLOB; pvReserved: PVOID;
  pPromptStruct: PCRYPTPROTECT_PROMPTSTRUCT; dwFlags: DWORD; pDataOut: PDATA_BLOB): BOOL; stdcall;

  BCryptOpenAlgorithmProvider:function(out phAlgorithm: BCRYPT_ALG_HANDLE;
  pszAlgId, pszImplementation: LPCWSTR; dwFlags: ULONG): TNTStatus; stdcall;

  BCryptSetProperty:function(hObject: BCRYPT_HANDLE; pszProperty: LPCWSTR;
  pbInput: PUCHAR; cbInput: ULONG; dwFlags: ULONG): TNTStatus; stdcall;

  BCryptGenerateSymmetricKey:function(hAlgorithm: BCRYPT_ALG_HANDLE;
    out phKey: BCRYPT_KEY_HANDLE; pbKeyObject: PUCHAR; cbKeyObject: ULONG;
    pbSecret: PUCHAR; cbSecret, dwFlags: ULONG): TNTStatus; stdcall;

    BCryptEncrypt:function(hKey: BCRYPT_KEY_HANDLE; pbInput: PUCHAR;
      cbInput: ULONG; pPaddingInfo: Pointer; pbIV: PUCHAR; cbIV: ULONG;
      pbOutput: PUCHAR; cbOutput: ULONG; out pcbResult: ULONG;
      dwFlags: ULONG): TNTStatus; stdcall;

    BCryptDecrypt:function(hKey: BCRYPT_KEY_HANDLE; pbInput: PUCHAR;
  cbInput: ULONG; pPaddingInfo: Pointer; pbIV: PUCHAR; cbIV: ULONG;
  pbOutput: PUCHAR; cbOutput: ULONG; out pcbResult: ULONG;
  dwFlags: ULONG): TNTStatus; stdcall;

implementation

uses uadvapi32; //to avoid circular reference


 type _GENERICKEY_BLOB =record
	 Header:BLOBHEADER;
	 dwKeyLen:DWORD;
end;
   GENERICKEY_BLOB=_GENERICKEY_BLOB;
   PGENERICKEY_BLOB=^GENERICKEY_BLOB;

type
  //{$align 8}
  _MY_BLOB = record
    cbData: DWORD;
    pbData: LPBYTE;
  end;

  type _RSAPUBKEY =record
             magic:DWORD;                  // Has to be RSA1
             bitlen:DWORD;                 // # of bits in modulus
             pubexp:DWORD;                 // public exponent
  end;                                        // Modulus data follows
  RSAPUBKEY=_RSAPUBKEY;
  PRSAPUBKEY=^_RSAPUBKEY;


const
BCRYPT_CHAIN_MODE_CBC_:widestring       = 'ChainingModeCBC';
BCRYPT_CHAIN_MODE_ECB_:widestring       = 'ChainingModeECB';
BCRYPT_CHAIN_MODE_CFB_:widestring       = 'ChainingModeCFB';
BCRYPT_CHAINING_MODE_ :widestring       = 'ChainingMode';
BCRYPT_CHAIN_MODE_GCM_:widestring       = 'ChainingModeGCM';





procedure RtlCopyMemory(Destination: PVOID; Source: PVOID; Length: SIZE_T); stdcall;
begin
  Move(Source^, Destination^, Length);
end;


//https://stackoverflow.com/questions/13145112/secure-way-to-store-password-in-windows

function CryptProtectData_(dataBytes:array of byte;var output:tbytes;flags:dword=0):boolean;overload;
var
  plainBlob,encryptedBlob:DATA_BLOB;
begin
  fillchar(plainBlob,sizeof(DATA_BLOB),0);
  fillchar(encryptedBlob,sizeof(DATA_BLOB),0);

  plainBlob.pbData :=@dataBytes[0]; //dataBytes;
  plainBlob.cbData := sizeof(dataBytes);

  result:=CryptProtectData(@plainBlob, nil, nil, nil, nil, flags, @encryptedBlob);
  if result=true then
     begin
     setlength(output,encryptedBlob.cbData);
     CopyMemory (@output[0],encryptedBlob.pbData,encryptedBlob.cbData);
     end;
end;

function CryptProtectData_(dataBytes:array of byte;filename:string;flags:dword=0):boolean;overload;
var
  plainBlob,encryptedBlob:_MY_BLOB;
  outfile:thandle{$ifdef fpc}=0{$endif fpc};
  byteswritten:dword{$ifdef fpc}=0{$endif fpc};
  //
  text:string;

begin
  result:=false;
  fillchar(plainBlob,sizeof(plainBlob),0);
  fillchar(encryptedBlob,sizeof(encryptedBlob),0);

  outFile := CreateFile(pchar(filename), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if outfile<=0 then exit;

  plainBlob.pbData := @dataBytes[0];
  plainBlob.cbData := length(dataBytes);
  log('length in:'+inttostr(length(dataBytes)));

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  result:=CryptProtectData(@plainBlob, nil, nil, nil, nil, flags, @encryptedBlob);
  log('cbData:'+inttostr(encryptedBlob.cbData) );
  if result=true then
     begin
     result:=WriteFile(outFile, encryptedBlob.pbData^, encryptedBlob.cbData, byteswritten, nil);
     log('byteswritten:'+inttostr(byteswritten));
     end;

  closehandle(outfile);

end;

function decodecred(cred:pointer):boolean;
const
  strSalt:string='abe2869f-9b47-4cd9-a358-c22904dba7f7';
  //82BD0E67-9FEA-4748-8672-D5EFE5B779B0 - domain entropy
var
  bytes:array of byte;//array[0..1023] of byte;
  //
  OptionalEntropy, datain,dataout:_MY_BLOB; //data_blob does not work? -> error 1783...
  tmpSalt:array [0..36] of word; //37 -> 74 -> 148
  i:integer;
begin
  log('**** decodecred ****');
  result:=true;
  //
  //writeln(sizeof(tmpsalt));
  fillchar(tmpSalt ,sizeof(tmpsalt),0);
  for i:=0 to 35 do
      begin
      tmpSalt[i] :=  ord(strSalt[i+1]) * 4;
      //write('\x'+inttohex(tmpSalt[i],2));
      end;
  //writeln;
  fillchar(OptionalEntropy,sizeof(OptionalEntropy),0);
  OptionalEntropy.pbData := @tmpSalt[0];
  OptionalEntropy.cbData := 74;
  //
  log('Flags:'+inttostr(PCREDENTIALW(cred)^.Flags)  ,1);
  log('Type_:'+inttostr(PCREDENTIALW(cred)^.Type_   ),1);
  if PCREDENTIALW(cred)^.TargetName<>nil then log('TargetName:'+widestring(PCREDENTIALW(cred)^.TargetName ),1);
  if PCREDENTIALW(cred)^.Comment<>nil then log('Comment:'+widestring(PCREDENTIALW(cred)^.Comment ),1);
  if PCREDENTIALW(cred)^.TargetAlias<>nil then log('TargetAlias:'+widestring(PCREDENTIALW(cred)^.TargetAlias ),1);
  if PCREDENTIALW(cred)^.UserName<>nil then log('UserName:'+widestring(PCREDENTIALW(cred)^.UserName ),1);
  log('CredentialBlobSize:'+inttostr(PCREDENTIALW(cred)^.CredentialBlobSize));
  if PCREDENTIALW(cred)^.CredentialBlobSize >0 then
             begin
               setlength(bytes,PCREDENTIALW(cred)^.CredentialBlobSize);
               //we could use entropy/salt + CryptUnprotectData
               CopyMemory (@bytes[0],PCREDENTIALW(cred)^.CredentialBlob,PCREDENTIALW(cred)^.CredentialBlobSize);
               if (PCREDENTIALW(cred)^.TargetName<>nil) and (pos('Microsoft_WinInet',strpas(PCREDENTIALW(cred)^.TargetName))>0) then
                  begin
                  fillchar(DataIn,sizeof(DataIn),0);
                  fillchar(DataOut,sizeof(DataOut),0);
                  DataIn.pbData := @bytes[0]; //PCREDENTIALW(cred)^.CredentialBlob;
                  DataIn.cbData := PCREDENTIALW(cred)^.CredentialBlobSize;
                  if CryptUnprotectData(@DataIn, nil, @OptionalEntropy, nil,nil,0,@DataOut)=true
                     then log('CredentialBlob:'+BytetoAnsiString (DataOut.pbData ,dataout.cbData ),1)
                     else log('CryptUnprotectData failed:'+inttostr(getlasterror),1);
                  //writeln(dataout.cbData );
                  end //if pos('Microsoft_WinInet',strpas(PCREDENTIALW(cred)^.TargetName))>0 then
                  else log('CredentialBlob:'+copy(BytetoAnsiString (bytes),1,PCREDENTIALW(cred)^.CredentialBlobSize),1);
             end;
end;

function removezero(buffer:array of byte):string;
var
  i:dword;
begin
result:='';
if length(buffer)=0 then exit;
for i:=0 to length(buffer)-1 do if buffer[i]<>0 then result:=result+chr(buffer[i]);
end;

function decodecredblob(cred:pointer):boolean;
var
  bytes:array[0..1023] of byte;
  localft:windows.FILETIME ;
  st:windows.SYSTEMTIME ;
  dw,offset:dword;
  tmp:array of byte;
begin
  result:=true;
  log('CredFlags:'+inttostr(PCRED_BLOB(cred)^.credFlags)  ,1);
  log('CredSize:'+inttostr(PCRED_BLOB(cred)^.credSize   ),1);
  log('Type:'+inttostr(PCRED_BLOB(cred)^.type_   ),1);
  log('Flags:'+inttostr(PCRED_BLOB(cred)^.Flags   ),1);
  //
  FileTimeToLocalFileTime (PCRED_BLOB(cred)^.LastWritten,localft) ;
  FileTimeToSystemTime(localft, st );
  log('LastWritten:'+DateTimeToStr (SystemTimeToDateTime (st)),1);
  //
  offset:=0;
  dw:=PCRED_BLOB(cred)^.data[0];
  //log('dwtargetname:'+inttostr(dw));
  setlength(tmp ,dw);
  zeromemory(@tmp[0],dw);
  copymemory(@tmp[0],@PCRED_BLOB(cred)^.data[offset+4],dw);
  log('TargetName:'+pwidechar(@tmp[0] ),1);
  zeromemory(@tmp[0],dw);
  //
  inc(offset,dw+sizeof(dword));
  dw:=PCRED_BLOB(cred)^.data[offset];
  //log('dwunkdata:'+inttostr(dw));
  setlength(tmp ,dw);
  copymemory(@tmp[0],@PCRED_BLOB(cred)^.data[offset+4],dw);
  log('Unkdata:'+pwidechar(@tmp[0] ),1);
  zeromemory(@tmp[0],dw);
  //
  inc(offset,dw+sizeof(dword));
  dw:=PCRED_BLOB(cred)^.data[offset];
  //log('dwcomment:'+inttostr(dw));
  setlength(tmp ,dw);
  copymemory(@tmp[0],@PCRED_BLOB(cred)^.data[offset+4],dw);
  log('Comment:'+pwidechar(@tmp[0] ),1);
  zeromemory(@tmp[0],dw);
  //
  inc(offset,dw+sizeof(dword));
  dw:=PCRED_BLOB(cred)^.data[offset];
  //log('dwtargetalias:'+inttostr(dw));
  setlength(tmp ,dw);
  copymemory(@tmp[0],@PCRED_BLOB(cred)^.data[offset+4],dw);
  log('Targetalias:'+pwidechar(@tmp[0] ),1);
  zeromemory(@tmp[0],dw);
  //
  inc(offset,dw+sizeof(dword));
  dw:=PCRED_BLOB(cred)^.data[offset];
  //log('dwusername:'+inttostr(dw));
  setlength(tmp ,dw);
  copymemory(@tmp[0],@PCRED_BLOB(cred)^.data[offset+4],dw);
  log('Username:'+pwidechar(@tmp[0] ),1);
  zeromemory(@tmp[0],dw);
  //
  inc(offset,dw+sizeof(dword));
  dw:=PCRED_BLOB(cred)^.data[offset];
  //log('CredentialBlobSize:'+inttostr(dw));
  setlength(tmp ,dw);
  copymemory(@tmp[0],@PCRED_BLOB(cred)^.data[offset+4],dw);
  //log('CredentialBlob:'+ pwidechar(@tmp[0] ),1);
  //log('CredentialBlob:'+BytetoAnsiString ( tmp ),1);
  log('CredentialBlob:'+removezero ( tmp ),1);
  zeromemory(@tmp[0],dw);
  //
end;

function decodecredhist(filename:string; credhist:pDPAPI_CREDHIST):boolean;
var
  buffer:array[0..4095] of byte;
  outfile:thandle{$ifdef fpc}=0{$endif fpc};
  bytesread:cardinal;
  offset,size:word;
  dw,sidlen,nextlen:dword;
  guid_:tguid;
  debug:byte;
  bytes:tbytes;
  stringsid:pchar;
  fsize:int64;
  label debut;
begin
  log('**** decodecredhist ****');
  //if credhist=nil then debug:=1 else debug:=0;
  debug:=1;
  //if credhist<>nil then ZeroMemory(credhist,4096);
  //
  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  Int64Rec(fsize).Lo := GetFileSize(outFile, @Int64Rec(fsize).Hi);
  if outfile=thandle(-1) then log('CreateFile:'+inttostr(getlasterror));
  if outfile=thandle(-1) then exit;
  bytesread:=0;
  result:=readfile(outfile ,buffer,4096,bytesread,nil);
  closehandle(outfile);
  //
  offset:=0;
  size:=0;
  //
  debut:
  //if nextlen>0 we should increase array of cred entries by 1 or we just loop thru the file...
  if credhist <>nil then
     begin
     setlength(credhist.entries,length(credhist.entries)+1);
     log('******** entry #'+inttostr(length(credhist.entries)-1)+' ********',1);
     end;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwVersion:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  CopyMemory( @guid_,@buffer[offset],sizeof(guid_));
  log('guid:'+GUIDToString(guid_),debug);
  inc(offset,sizeof(guid_));
  //
  CopyMemory( @nextlen,@buffer[offset],sizeof(nextlen));
  log('dwNextLen:'+inttohex(nextlen,4),debug);
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwType:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('algHash:'+inttohex(dw,4),debug);
  inc(offset,4);
  if credhist <>nil then credhist.entries [high(credhist.entries)].algHash :=dw;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('rounds:'+inttohex(dw,4),debug);
  inc(offset,4);
  if credhist <>nil then credhist.entries [high(credhist.entries)].rounds :=dw;
  //
  CopyMemory( @sidlen,@buffer[offset],sizeof(sidlen));
  log('sidLen:'+inttohex(sidlen,4),debug);
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('algCrypt:'+inttohex(dw,4),debug);
  inc(offset,4);
  if credhist <>nil then credhist.entries [high(credhist.entries)].algCrypt :=dw;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('sha1Len:'+inttohex(dw,4),debug);
  inc(offset,4);
  if credhist <>nil then credhist.entries [high(credhist.entries)].sha1Len :=dw;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('md4Len:'+inttohex(dw,4),debug);
  inc(offset,4);
  if credhist <>nil then credhist.entries [high(credhist.entries)].md4Len :=dw;
  //
  setlength(bytes,16);
  CopyMemory( @bytes[0],@buffer[offset],16);
  log('salt:'+ByteToHexaString (bytes),debug);
  if credhist <>nil then CopyMemory( @credhist.entries [high(credhist.entries)].salt[0],@buffer[offset],16);
  inc(offset,16);
  //
  setlength(bytes,sidlen);
  CopyMemory( @bytes[0],@buffer[offset],sidlen);
  log('sid:'+ByteToHexaString (bytes),debug);
  if ConvertSidToStringSidA(@bytes[0] ,stringsid) then
    begin
    log('---:'+strpas(stringsid),1);
    credhist.entries [high(credhist.entries)].stringsid :=strpas(stringsid);
    localfree(cardinal(stringsid));
    end; // else log('ConvertSidToStringSidA failed',0);
  if credhist <>nil then
     begin
     credhist.entries [high(credhist.entries)].psid:=allocmem(sidlen);
     CopyMemory( credhist.entries [high(credhist.entries)].psid,@bytes[0],sidlen);
     end;
  inc(offset,sidlen);
  //
  setlength(bytes,$30); //hardcoded - we need to read the last 4 bytes and compute size from here
  CopyMemory( @bytes[0],@buffer[offset],$30);
  log('psecret:'+ByteToHexaString (bytes),debug);
  if credhist <>nil then
     begin
     setlength(credhist.entries [high(credhist.entries)].pSecret,$30);
     CopyMemory( @credhist.entries [high(credhist.entries)].pSecret[0],@buffer[offset],$30);
     credhist.entries [high(credhist.entries)].__dwSecretLen :=$30;
     end;
  inc(offset,$30);
  //
  if size=0 then size:=offset;
  //writeln(size);
  //writeln(fsize);
  //writeln(offset);
  if offset+size>fsize then exit else goto debut; //more entries to come

end;

function decodemk(filename:string; mk:pmasterkey):boolean;
var
  buffer:array[0..4095] of byte;
  outfile:thandle{$ifdef fpc}=0{$endif fpc};
  bytesread:cardinal;
  MasterKeyLen,offset:word;
  dw:dword;
  pw:pwidechar;
  bytes:tbytes;
  debug:byte;
begin
  log('**** decodemk ****');
  if mk=nil then debug:=1 else debug:=0;
  if mk<>nil then ZeroMemory(mk,sizeof(tmasterkey));
  //
  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  if outfile=thandle(-1) then log('CreateFile:'+inttostr(getlasterror));
  if outfile=thandle(-1) then exit;
  bytesread:=0;
  result:=readfile(outfile ,buffer,4096,bytesread,nil);
  closehandle(outfile);
  //
  offset:=0;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwVersion:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  inc(offset,8); //dummy
  //
  pw:=AllocMem ($48);
  CopyMemory(pw,@buffer[offset],$48);
  log('szGuid:'+string(widestring(pw)),debug);
  inc(offset,$48);
  if mk<>nil then mk.szGuid :=StringToGUID ('{'+string(widestring(pw))+'}') ;
  //
  inc(offset,8); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwFlags:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwMasterKeyLen:'+inttohex(dw,4),debug);
  //mk.dwMasterKeyLen:=dw;
  inc(offset,4);
  MasterKeyLen:=dw-32;
  //
  inc(offset,4); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwBackupKeyLen:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  inc(offset,4); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwCredHistLen:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  inc(offset,4); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwDomainKeyLen:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  inc(offset,4); //dummy
  //
  log('MasterKey',debug);
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('dwVersion:'+inttohex(dw,4),debug);
  inc(offset,4);
  //
  SetLength(bytes,16);;
  CopyMemory (@bytes[0],@buffer[offset],16);
  log('Salt:'+ByteToHexaString(bytes),debug);
  if mk<>nil then CopyMemory (@mk.Salt[0],@buffer[offset],16);
  inc(offset,16);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('rounds:'+inttohex(dw,4),debug);
  inc(offset,4);
  if mk<>nil then mk.rounds:=dw;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('algHash:'+inttohex(dw,4),debug);
  inc(offset,4);
  if mk<>nil then mk.algHash:=dw;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  log('algCrypt:'+inttohex(dw,4),debug);
  inc(offset,4);
  if mk<>nil then mk.algCrypt:=dw;
  //
  SetLength(bytes,MasterKeyLen);;
  CopyMemory (@bytes[0],@buffer[offset],MasterKeyLen);
  log('pbKey:'+ByteToHexaString(bytes),debug);
  if mk<>nil then
     begin
     setlength(mk.pbKey,MasterKeyLen);
     CopyMemory (@mk.pbKey[0],@buffer[offset],MasterKeyLen);
     end;
  inc(offset,MasterKeyLen);
  //
end;

function decodeblob(buffer:tbytes;blob:pdpapi_blob;debug:byte=1):boolean;overload;
const
marker:array[0..15] of byte=($D0,$8C,$9D,$DF,$01,$15,$D1,$11,$8C,$7A,$00,$C0,$4F,$C2,$97,$EB);
var
  i,offset:word;
  dw:dword;
  pw:pwidechar;
  guid_:tguid;
  bytes:tbytes;
  //debug:byte;
begin
  log('**** decodeblob ****');
  offset:=0;
  //if blob=nil then debug:=1 else debug:=0;
  if blob<>nil then ZeroMemory(blob,sizeof(tdpapi_blob));
    for i:=0 to 511 do //look for first 512 bytes...
        begin
          if CompareMem (@buffer[i],@marker[0],16) then begin offset:=i;break;end;
        end;
    //if offset=0 then exit;
    if offset=0 then begin log('dpapi guid not found? assuming offset=0');offset:=4;end;
    //
    CopyMemory( @dw,@buffer[offset-4],sizeof(dw));
    log('dwVersion:'+inttohex(dw,4),debug);
    //
    CopyMemory( @guid_,@buffer[offset],sizeof(guid_));
    log('GuidProvider:'+GUIDToString(guid_),debug);
    inc(offset,16);
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwMasterKeyVersion:'+inttohex(dw,4),debug);
    inc(offset,4);
    //
    CopyMemory( @guid_,@buffer[offset],sizeof(guid_));
    log('GuidMasterKey:'+GUIDToString(guid_),debug);
    if blob<>nil then blob.guidMasterKey:=guid_;
    inc(offset,16);
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwFlags:'+inttohex(dw,4),debug);
    inc(offset,4);
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwDescriptionLen:'+inttostr(dw),debug);
    inc(offset,4);
    if dw>0 then
       begin
       pw:=AllocMem (dw);
       copymemory(pw,@buffer[offset],dw);
       //writeln('szDescription:'+(  StringReplace ( string(widestring(pw)),'#13#10','',[]) ));
       log('szDescription:'+(  string(widestring(pw)) ),debug);
       inc(offset,dw);
       end;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('algCrypt:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if blob<>nil then blob.algCrypt:=dw;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwAlgCryptLen:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if blob<>nil then blob.dwAlgCryptLen :=dw;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwSaltLen:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if blob<>nil then blob.dwSaltLen:=dw;
    if dw>0 then
       begin
       SetLength(bytes,dw);;
       CopyMemory (@bytes[0],@buffer[offset],dw);
       if blob<>nil then
          begin
          setlength(blob.pbSalt ,dw);
          CopyMemory (@blob.pbSalt[0],@buffer[offset],dw);
          end;
       log('pbSalt:'+ByteToHexaString(bytes),debug);
       inc(offset,dw);
       end;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwHmacKeyLen:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if dw>0 then
       begin
       SetLength(bytes,dw);;
       CopyMemory (@bytes[0],@buffer[offset],dw);
       log('pbHmackKey:'+ByteToHexaString(bytes),debug);
       inc(offset,dw);
       end;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('algHash:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if blob<>nil then blob.algHash:=dw;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwAlgHashLensh:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if blob<>nil then blob.dwAlgHashLen:=dw;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwHmac2KeyLen:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if dw>0 then
       begin
       SetLength(bytes,dw);;
       CopyMemory (@bytes[0],@buffer[offset],dw);
       log('pbHmack2Key:'+ByteToHexaString(bytes),debug);
       inc(offset,dw);
       end;
    //       i,offset:word;
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwDataLen:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if blob<>nil then blob.dwDataLen :=dw;
    if dw>0 then
       begin
       SetLength(bytes,dw);;
       CopyMemory (@bytes[0],@buffer[offset],dw);
       if blob<>nil then
          begin
          setlength(blob.pbData ,dw);
          CopyMemory (@blob.pbData[0],@buffer[offset],dw);
          end;
       log('pbData:'+ByteToHexaString(bytes),debug);
       inc(offset,dw);
       end;
    //
    CopyMemory( @dw,@buffer[offset],sizeof(dw));
    log('dwSignLen:'+inttohex(dw,sizeof(dw)),debug);
    inc(offset,4);
    if dw>0 then
       begin
       SetLength(bytes,dw);;
       CopyMemory (@bytes[0],@buffer[offset],dw);
       log('pbSign:'+ByteToHexaString(bytes),debug);
       inc(offset,dw);
       end;
    //
    result:=true;
end;

//function decodeblob(filename:string;var blob:tdpapi_blob):boolean;overload;
function decodeblob(filename:string;blob:pdpapi_blob;debug:byte=1):boolean;overload;
const
marker:array[0..15] of byte=($D0,$8C,$9D,$DF,$01,$15,$D1,$11,$8C,$7A,$00,$C0,$4F,$C2,$97,$EB);
var
  //buffer:array[0..4095] of byte;
  buffer:tbytes;
  outfile:thandle{$ifdef fpc}=0{$endif fpc};
  bytesread:cardinal;
  i,offset:word;
  guid:tguid;
  dw:dword;
  pw:pwidechar;
  bytes:tbytes;
begin
  //
  log('**** decodeblob ****');
  log('filename:'+filename);
  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN , 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM , 0);
  //if outfile=thandle(-1) then   outFile := CreateFile(pchar(filename), GENERIC_READ, FILE_SHARE_READ , nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  //if outfile=thandle(-1) then   outFile := CreateFile(pchar(filename), GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE , nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  //if outfile=thandle(-1) then   outFile := CreateFile(pchar(filename), GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE , nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  if outfile=thandle(-1) then
     begin
     log('CreateFile:'+inttostr(getlasterror));
     exit;
     end;
  bytesread:=0;
  setlength(buffer,4096);
  result:=readfile(outfile ,buffer[0],length(buffer),bytesread,nil);
  closehandle(outfile);
  log('bytesread:'+inttostr(bytesread));
  log('result:'+booltostr(result));
  if (result=false) or (bytesread=0) then exit;
  //
  result:=decodeblob (buffer,blob,debug);

end;





function crypto_hash(algid:alg_id;data:LPCVOID;dataLen:DWORD;  hash:lpvoid;hashWanted:DWORD):boolean;
var
        status:BOOL {$ifdef fpc}=FALSE{$endif fpc};
  	hProv:HCRYPTPROV;
  	hHash:HCRYPTHASH;
  	hashLen:DWORD;
  	buffer:PBYTE;
  	//PKERB_CHECKSUM pCheckSum;
  	Context:PVOID;
begin
log('**** crypto_hash ****');
  //writeln(inttohex(CALG_SHA1,4));writeln(inttohex(CALG_MD4,4));writeln(inttohex(CALG_MD5,4));
  log('datalen:'+inttostr(datalen));
  result:=false;
  if CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  	begin
        log('CryptAcquireContext OK');
  		if CryptCreateHash(hProv, algid, 0, 0, hHash) then
  		begin
                log('CryptCreateHash OK');
  			if CryptHashData(hHash, data, dataLen, 0) then
  			begin
                        log('CryptHashData OK');
  				if CryptGetHashParam(hHash, HP_HASHVAL, nil, hashLen, 0) then
  				begin
                                log('CryptGetHashParam OK:'+inttostr(hashLen));
                                buffer:=Pointer(LocalAlloc(LPTR, hashLen));
  					if buffer<>nil  then
  					begin
                                        log('LocalAlloc OK');
  						result := CryptGetHashParam(hHash, HP_HASHVAL, buffer, hashLen, 0);
                                                log('CryptGetHashParam:'+BoolToStr(result,true));
                                                //RtlCopyMemory(pointer(hash), buffer, min(hashLen, hashWanted));
                                                log('hashLen:'+inttostr(hashLen));
                                                log('hashWanted:'+inttostr(hashWanted));
                                                //log(inttohex(hHash,sizeof(pointer)));
                                                CopyMemory (hash, buffer, min(hashLen, hashWanted));
                                                //log('HASH:'+ByteToHexaString (buffer^),1);
                                                //
                                                LocalFree(thandle(buffer));
  					end;//if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen))
  				end; //CryptGetHashParam
  			end; //CryptHashData
  			CryptDestroyHash(hHash);
  		end; //CryptCreateHash
  		CryptReleaseContext(hProv, 0);
        end; //CryptAcquireContext
        log('**** crypto_hash:'+BoolToStr (result)+' ****');
end;

function crypto_hash_(algid:alg_id;data:LPCVOID;dataLen:DWORD; var output:tbytes;hashWanted:DWORD):boolean;
var
  ptr_:lpvoid;
begin
  //ptr_:=allocmem(hashWanted);
  SetLength(output,hashWanted );
  ZeroMemory(@output[0],hashWanted );
  //result:=crypto_hash(algid,data,dataLen,ptr_,hashWanted );
  result:=crypto_hash(algid,data,dataLen,@output[0],hashWanted );
  //CopyMemory(@output[0],ptr_,hashWanted ) ;
  //Freemem (ptr_ );
end;

function CryptUnProtectData_(filename:string;var dataBytes:tbytes;const AdditionalEntropy: string=''):boolean;overload;
var
  plainBlob,decryptedBlob:_MY_BLOB;
  outfile:thandle{$ifdef fpc}=0{$endif fpc};
  byteswritten:dword{$ifdef fpc}=0{$endif fpc};
  //
  text:string;
  buffer:array[0..4095] of byte;
  bytesread:cardinal;
  //
  entropyBlob: DATA_BLOB;
  pEntropy: Pointer;
begin
  log('**** CryptUnProtectData_ ****');
  result:=false;
  fillchar(plainBlob,sizeof(plainBlob),0);
  fillchar(decryptedBlob,sizeof(decryptedBlob),0);

  if not FileExists(filename) then log('filename does not exist');

  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_HIDDEN , 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_ARCHIVE, 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_ARCHIVE or FILE_ATTRIBUTE_SYSTEM, 0);
  if outfile=thandle(-1) then log('CreateFile:'+inttostr(getlasterror));
  if outfile=thandle(-1) then exit;
  result:=readfile(outfile ,buffer,4096,bytesread,nil);
  if (result=false) or (bytesread=0) then log('readfile:'+inttostr(getlasterror)+' '+inttostr(outfile));
  log('bytesread:'+inttostr(bytesread));

  if AdditionalEntropy <> '' then
    begin
        entropyBlob.pbData := Pointer(AdditionalEntropy);
        entropyBlob.cbData := Length(AdditionalEntropy)*SizeOf(Char);
        pEntropy := @entropyBlob;
    end
    else
        pEntropy := nil;

  plainBlob.pbData := @buffer[0];
  //plainBlob.pbData:=getmem(bytesread);
  //copymemory(plainBlob.pbData,@buffer[0],bytesread);
  plainBlob.cbData := bytesread;
  log('plainBlob.cbData:'+inttostr(plainBlob.cbData) );

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  decryptedBlob.pbData :=nil; //getmem(4096); //@databytes[0];

  //3rd param is entropy
  //5th param is password
  result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, 0{CRYPTPROTECT_LOCAL_MACHINE}, @decryptedBlob);
  if result=false then
     begin
     log('trying CRYPTPROTECT_LOCAL_MACHINE...');
     result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, CRYPTPROTECT_LOCAL_MACHINE, @decryptedBlob);
     end;

  log('decryptedBlob.cbData:'+inttostr(decryptedBlob.cbData) );
  //log(ByteToHexaString (decryptedBlob.pbData,decryptedBlob.cbData) );
  //log(strpas(pchar(decryptedBlob.pbData)));
  if result=true then
    begin
    setlength(databytes,decryptedBlob.cbData);
    CopyMemory(@databytes[0],decryptedBlob.pbData,decryptedBlob.cbData);
    end;
  if result=false then log('CryptUnProtectData_ lasterror:'+inttostr(getlasterror));

  closehandle(outfile);

end;

function CryptUnProtectData_(buffer:tbytes;var output:tbytes;const AdditionalEntropy: string=''):boolean;overload;
var
  plainBlob,decryptedBlob:_MY_BLOB;
  byteswritten:dword{$ifdef fpc}=0{$endif fpc};
  //
  text:string;
  //buffer:array[0..4095] of byte;
  //
  entropyBlob: DATA_BLOB;
  pEntropy: Pointer;
begin
  log('**** CryptUnProtectData_ ****');
  result:=false;

  fillchar(plainBlob,sizeof(plainBlob),0);
  fillchar(decryptedBlob,sizeof(decryptedBlob),0);

  if AdditionalEntropy <> '' then
    begin
        entropyBlob.pbData := Pointer(AdditionalEntropy);
        entropyBlob.cbData := Length(AdditionalEntropy)*SizeOf(Char);
        pEntropy := @entropyBlob;
    end
    else
        pEntropy := nil;


  plainBlob.pbData := @buffer[0];
  //plainBlob.pbData:=getmem(bytesread);
  //copymemory(plainBlob.pbData,@buffer[0],bytesread);
  plainBlob.cbData := length(buffer);
  log('plainBlob.cbData:'+inttostr(plainBlob.cbData) );

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  decryptedBlob.pbData :=nil; //getmem(4096); //@databytes[0];
  //3rd param entropy
  result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, 0{CRYPTPROTECT_LOCAL_MACHINE}, @decryptedBlob);
  if result=false then result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, CRYPTPROTECT_LOCAL_MACHINE, @decryptedBlob);

  log('decryptedBlob.cbData:'+inttostr(decryptedBlob.cbData) );
  if result=true then
    begin
    setlength(output,decryptedBlob.cbData);
    CopyMemory(@output[0],decryptedBlob.pbData,decryptedBlob.cbData);
    end;
  if result=false then log('CryptUnProtectData_ lasterror:'+inttostr(getlasterror));


end;

function bencrypt(algo:lpcwstr;decrypted:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
var
  hProvider:BCRYPT_ALG_HANDLE{$ifdef fpc}=0{$endif fpc};
  encrypted:array[0..1023] of byte;
  hkey:BCRYPT_KEY_HANDLE{$ifdef fpc}=0{$endif fpc};
  status:NTSTATUS;
  encryptedPassLen,cbiv:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
  result:=0;
  cbiv:=0;
  {$ifdef fpc}log('algo:'+strpas(algo) ){$endif fpc};
  {
  log('encrypted size:'+inttostr(sizeof(encryped) ));
  log('decrypted size:'+inttostr(sizeof(decrypted) ));
  log('decrypted length:'+inttostr(length(decrypted) ));
  log('sizeof(gkey):'+inttostr(sizeof(gkey)));
  log('sizeof(iv):'+inttostr(sizeof(initializationVector )));
  }
  status:=BCryptOpenAlgorithmProvider(hProvider, algo, nil, 0);
  //log('hProvider:'+inttostr(hProvider));
  if status<>0 then begin log('BCryptOpenAlgorithmProvider NOT OK');exit;end;
  if algo=BCRYPT_AES_ALGORITHM then
     begin
       status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CFB_[1], sizeof(BCRYPT_CHAIN_MODE_CFB_), 0);
       cbiv:=sizeof(initializationVector );
     end;
  if algo=BCRYPT_3DES_ALGORITHM then
     begin
       status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CBC_[1], sizeof(BCRYPT_CHAIN_MODE_CBC_), 0);
       cbiv:=sizeof(initializationVector ) div 2;
     end;
  //writeln('cbiv:'+inttostr(cbiv));
  if status<>0 then begin log('BCryptSetProperty NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  status:=BCryptGenerateSymmetricKey(hProvider, hkey, nil, 0, @gKey[0], sizeof(gKey), 0);
  if status<>0 then begin log('BCryptGenerateSymmetricKey NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  //writeln('hkey:'+inttostr(hkey));
  //fillchar(decrypted,sizeof(decrypted ),0);
  fillchar(encrypted,length(encrypted ),0);
  if length(initializationVector)>0
     then status := BCryptEncrypt(hkey, @decrypted[0], sizeof(decrypted), 0, @initializationVector[0], cbiv, @encrypted[0], length(encrypted), result, 0)
     else status := BCryptEncrypt(hkey, @decrypted[0], sizeof(decrypted), 0, nil, 0, @encrypted[0], length(encrypted), result, 0);
  if status<>0 then begin log('BCryptDecrypt NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  log('resultlen:'+inttostr(result));
  log('encrypted:'+ByteToHexaString  (encrypted  ));
  //log(strpas (pwidechar(@decrypted[0]) ));
  copymemory(output,@encrypted[0],result);
  //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  //0xC0000023  STATUS_BUFFER_TOO_SMALL
end;


function bdecrypt(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte;CHAINING_MODE:widestring=''):ULONG;
var
  hProvider:BCRYPT_ALG_HANDLE{$ifdef fpc}=0{$endif fpc};
  decrypted:array[0..1023] of byte;
  hkey:BCRYPT_KEY_HANDLE{$ifdef fpc}=0{$endif fpc};
  status:NTSTATUS;
  decryptedPassLen,cbiv:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
  log('**** bdecrypt ****');
  result:=0;
  cbiv:=0;
  {$ifdef fpc}log('algo:'+strpas(algo) ){$endif fpc};
  {
  log('encrypted size:'+inttostr(sizeof(encryped) ));
  log('decrypted size:'+inttostr(sizeof(decrypted) ));
  log('decrypted length:'+inttostr(length(decrypted) ));
  log('sizeof(gkey):'+inttostr(sizeof(gkey)));
  log('sizeof(iv):'+inttostr(sizeof(initializationVector )));
  }
  status:=BCryptOpenAlgorithmProvider(hProvider, algo, nil, 0);
  //log('hProvider:'+inttostr(hProvider));
  if status<>0 then begin log('BCryptOpenAlgorithmProvider NOT OK');exit;end;
  //https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
  if algo=BCRYPT_AES_ALGORITHM then
     begin
       if  CHAINING_MODE=''
          then status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CFB_[1], sizeof(BCRYPT_CHAIN_MODE_CFB_), 0)
          else status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @CHAINING_MODE[1], sizeof(CHAINING_MODE), 0);
       cbiv:=sizeof(initializationVector );
     end;
  if algo=BCRYPT_3DES_ALGORITHM then
     begin
       if  CHAINING_MODE=''
          then status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CBC_[1], sizeof(BCRYPT_CHAIN_MODE_CBC_), 0)
          else status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @CHAINING_MODE[1], sizeof(CHAINING_MODE), 0);
       cbiv:=sizeof(initializationVector ) div 2;
     end;
  //writeln('cbiv:'+inttostr(cbiv));
  if status<>0 then begin log('BCryptSetProperty NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  status:=BCryptGenerateSymmetricKey(hProvider, hkey, nil, 0, @gKey[0], sizeof(gKey), 0);
  if status<>0 then begin log('BCryptGenerateSymmetricKey NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  //writeln('hkey:'+inttostr(hkey));
  //fillchar(decrypted,sizeof(decrypted ),0);
  fillchar(decrypted,length(decrypted ),0);
  //status := BCryptDecrypt(hkey, @encryped[0], sizeof(encryped), 0, @initializationVector[0], cbiv, @decrypted[0], sizeof(decrypted), result, 0);
  status := BCryptDecrypt(hkey, @encryped[0], sizeof(encryped), 0, @initializationVector[0], cbiv, @decrypted[0], length(decrypted), result, 0);
  if status<>0 then begin log('BCryptDecrypt NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  log('resultlen:'+inttostr(result));
  //log('decrypted:'+ByteToHexaString  (@decrypted[0],result  ));
  log('decrypted:'+ByteToHexaString  (decrypted));
  //log(strpas (pwidechar(@decrypted[0]) ));
  if output=nil then output:=allocmem(result);
  copymemory(output,@decrypted[0],result);
  //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  //0xC0000023  STATUS_BUFFER_TOO_SMALL
end;

function bdecrypt_gcm(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
const AES_BLOCK_SIZE=16 ;
var
  hProvider:BCRYPT_ALG_HANDLE{$ifdef fpc}=0{$endif fpc};
  decrypted:array[0..1023] of byte;
  hkey:BCRYPT_KEY_HANDLE{$ifdef fpc}=0{$endif fpc};
  status:NTSTATUS;
  decryptedPassLen,cbiv:ULONG;
  //gInitializationVector:array[0..15] of uchar;
  info:BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
begin
  log('**** bdecrypt_gcm ****');
  result:=0;
  cbiv:=0;
  {
  log('algo:'+strpas(algo) );
  log('encrypted size:'+inttostr(sizeof(encryped) ));
  log('decrypted size:'+inttostr(sizeof(decrypted) ));
  log('decrypted length:'+inttostr(length(decrypted) ));
  log('sizeof(gkey):'+inttostr(sizeof(gkey)));
  log('sizeof(iv):'+inttostr(sizeof(initializationVector )));
  }
  status:=BCryptOpenAlgorithmProvider(hProvider, algo, nil, 0);
  //log('hProvider:'+inttostr(hProvider));
  if status<>0 then begin log('BCryptOpenAlgorithmProvider NOT OK');exit;end;
  //https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
  if algo=BCRYPT_AES_ALGORITHM then
     begin
       status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_GCM_[1], sizeof(BCRYPT_CHAIN_MODE_GCM_), 0);
       cbiv:=sizeof(initializationVector );
     end;
  if algo=BCRYPT_3DES_ALGORITHM then
     begin
        status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_GCM_[1], sizeof(BCRYPT_CHAIN_MODE_GCM_), 0);
       cbiv:=sizeof(initializationVector ) div 2;
     end;
  //writeln('cbiv:'+inttostr(cbiv));
  if status<>0 then begin log('BCryptSetProperty NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  status:=BCryptGenerateSymmetricKey(hProvider, hkey, nil, 0, @gKey[0], sizeof(gKey), 0);
  if status<>0 then begin log('BCryptGenerateSymmetricKey NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  //writeln('hkey:'+inttostr(hkey));
  //fillchar(decrypted,sizeof(decrypted ),0);
  fillchar(decrypted,length(decrypted ),0);
  //
  fillchar(info,sizeof(info),0);
  info.cbSize :=sizeof(info); //Do not set this field directly. Use the BCRYPT_INIT_AUTH_MODE_INFO macro instead.
  info.dwInfoVersion :=1;
  info.pbNonce :=@initializationVector [0]; //iv
  info.cbNonce :=sizeof(initializationVector);
  info.pbTag :=@encryped[sizeof(encryped )-AES_BLOCK_SIZE]; //tag
  info.cbTag :=AES_BLOCK_SIZE;
  //log('pbTag:'+ByteToHexaString  (@encryped[sizeof(encryped )-AES_BLOCK_SIZE],AES_BLOCK_SIZE));
  //
  //status := BCryptDecrypt(hkey, @encryped[0], sizeof(encryped), 0, @initializationVector[0], cbiv, @decrypted[0], sizeof(decrypted), result, 0);
  status := BCryptDecrypt(hkey, @encryped[0], sizeof(encryped)-AES_BLOCK_SIZE, @info, nil, 0, @decrypted[0], length(decrypted), result, 0);
  log('resultlen:'+inttostr(result));
  //C000A002	STATUS_AUTH_TAG_MISMATCH
  if status<>0 then begin log('BCryptDecrypt NOT OK:'+inttohex(status,sizeof(status)));result:=0;exit;end;
  //
  log('decrypted:'+ByteToHexaString  (@decrypted[0],result));
  //log(strpas (pwidechar(@decrypted[0]) ));
  if output=nil then output:=allocmem(result);
  copymemory(output,@decrypted[0],result);
  //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  //0xC0000023  STATUS_BUFFER_TOO_SMALL
end;

{
function _bdecryptDES(encrypedPass:array of byte;gDesKey,initializationVector:array of byte):ULONG;
var
  hDesProvider:BCRYPT_ALG_HANDLE;
  decryptedPass:array[0..1023] of byte; //puchar;
  hDes:BCRYPT_KEY_HANDLE;
  status:NTSTATUS;
  //decryptedPassLen:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
   //3des
  BCryptOpenAlgorithmProvider(hDesProvider, pwidechar(BCRYPT_3DES_ALGORITHM), nil, 0);
  BCryptSetProperty(hDesProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CBC_[1], sizeof(BCRYPT_CHAIN_MODE_CBC_), 0);
  BCryptGenerateSymmetricKey(hDesProvider, hDes, nil, 0, @gDesKey[0], sizeof(gDesKey), 0);
  status := BCryptDecrypt(hDes, @encrypedPass[0], sizeof(encrypedPass), 0, @initializationVector[0], sizeof(initializationVector ) div 2, @decryptedPass[0], sizeof(decryptedPass), result, 0);

end;
}

{
function _bdecryptAES(encrypedPass:array of byte;gAesKey,initializationVector:array of byte):ULONG;
var
  hprovider:BCRYPT_ALG_HANDLE;
  decryptedPass:array[0..1023] of byte; //puchar;
  hAes:BCRYPT_KEY_HANDLE;
  status:NTSTATUS;
  //decryptedPassLen:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
  //aes
  BCryptOpenAlgorithmProvider(hProvider, pwidechar(BCRYPT_AES_ALGORITHM), nil, 0);
  BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE), @BCRYPT_CHAIN_MODE_CFB_[1], sizeof(BCRYPT_CHAIN_MODE_CFB_), 0);
  BCryptGenerateSymmetricKey(hProvider, hAes, nil, 0, @gAesKey[0], sizeof(gAesKey), 0);
  status := BCryptDecrypt(hAes, @encrypedPass[0], sizeof(encrypedPass), 0, @initializationVector[0], sizeof(initializationVector ) div 2, @decryptedPass[0], sizeof(decryptedPass), result, 0);

end;
}

//similar to kull_m_crypto_genericAES128Decrypt in mimikatz
function DecryptAES128(const Key: tbyte16;const IV:array of byte;const data: tbyte16;var output:tbyte16): boolean;
var
  pbData: PByte;
  hCryptProvider: HCRYPTPROV;
  KeyBlob: packed record
    Header: BLOBHEADER;
    Size: DWORD;
    Data: array[0..15] of Byte;
  end;
  hKey, hDecryptKey: HCRYPTKEY;
  dwKeyCypherMode: DWORD;
  ResultLen: DWORD;
//const
  //PROV_RSA_AES = 24;
  //CALG_AES_128 = $0000660e;
  //AESFinal = True;
begin
  Result := false;
  // MS_ENH_RSA_AES_PROV
  if CryptAcquireContext(hCryptProvider, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  begin
    log('CryptAcquireContext OK',0);
    KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
    keyBlob.Header.bVersion := CUR_BLOB_VERSION;
    keyBlob.Header.reserved := 0;
    keyBlob.Header.aiKeyAlg := CALG_AES_128;
    keyBlob.Size := Length(Key);
    CopyMemory(@keyBlob.Data[0], @Key[0], keyBlob.Size);

    if CryptImportKey(hCryptProvider, @KeyBlob, SizeOf(KeyBlob), 0, 0, hKey) then
    begin
      log('CryptImportKey OK',0);
      if CryptDuplicateKey(hKey, nil, 0, hDecryptKey) then
      begin
        log('CryptDuplicateKey OK',0);
        dwKeyCypherMode := CRYPT_MODE_CBC; //CRYPT_MODE_CBC or CRYPT_MODE_ECB
        if CryptSetKeyParam(hDecryptKey, KP_MODE, @dwKeyCypherMode, 0)=false then log('CryptSetKeyParam NOT OK',0);
        if CryptSetKeyParam(hDecryptKey, KP_IV, @IV[0], 0)=false then log('CryptSetKeyParam NOT OK',0);


        //output:=value;
        //pbData := @output[0];

        ResultLen :=sizeof(output);
        CopyMemory(@output[0],@data[0],sizeof(output));

        // the calling application sets the DWORD value to the number of bytes to be decrypted. Upon return, the DWORD value contains the number of bytes of the decrypted plaintext.
        if CryptDecrypt(hDecryptKey, 0, true, 0, @output[0] {pbData}, ResultLen) then
        begin
          log('CryptDecrypt OK',0);
          //SetLength(Result, ResultLen);
          result:=true;
        end
        else
        begin
          //NT_BAD_DATA (0x80090005)
          log('ResultLen:'+inttostr(ResultLen),0);
          if ResultLen >0 then result:=true else result:=false;
          log('CryptDecrypt NOT OK '+ IntTohex(GetLastError,4),0);
          Result := true;
        end;

        CryptDestroyKey(hDecryptKey);
      end;

      CryptDestroyKey(hKey);
    end;

    CryptReleaseContext(hCryptProvider, 0);
  end;
end;

{
function DecryptAES256(const Key: tbytes;const IV:array of byte;const data: tbytes;var output:tbytes): boolean;
var
  pbData: PByte;
  hCryptProvider: HCRYPTPROV;
  KeyBlob: packed record
    Header: BLOBHEADER;
    Size: DWORD;
    Data: array[0..31] of Byte;
  end;
  hKey, hDecryptKey: HCRYPTKEY;
  dwKeyCypherMode: DWORD;
  ResultLen: DWORD;
//const
const MS_ENH_RSA_AES_PROV:pchar='Microsoft Enhanced RSA and AES Cryptographic Provider'+#0;
  //PROV_RSA_AES = 24;
  //CALG_AES_128 = $0000660e;
  //AESFinal = True;
begin
  Result := false;
  // MS_ENH_RSA_AES_PROV
  if CryptAcquireContext(hCryptProvider, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  begin
    log('CryptAcquireContext OK',0);
    KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
    keyBlob.Header.bVersion := CUR_BLOB_VERSION;
    keyBlob.Header.reserved := 0;
    keyBlob.Header.aiKeyAlg := CALG_AES_256 ;
    keyBlob.Size := Length(Key);
    CopyMemory(@keyBlob.Data[0], @Key[0], keyBlob.Size);

    if CryptImportKey(hCryptProvider, @KeyBlob, SizeOf(KeyBlob), 0, 0, hKey) then
    begin
      log('CryptImportKey OK',0);
      if CryptDuplicateKey(hKey, nil, 0, hDecryptKey) then
      begin
        log('CryptDuplicateKey OK',0);
        dwKeyCypherMode := 5; //GCM ?
        if CryptSetKeyParam(hDecryptKey, KP_MODE, @dwKeyCypherMode, 0)=false then log('CryptSetKeyParam1 NOT OK',0);
        if CryptSetKeyParam(hDecryptKey, KP_IV, @IV[0], 0)=false then log('CryptSetKeyParam2 NOT OK',0);

        //output:=value;
        //pbData := @output[0];

        ResultLen :=length(output);
        //setlength(data,ResultLen);
        CopyMemory(@output[0],@data[0],ResultLen);
        log('ResultLen:'+inttostr(ResultLen),0);

        // the calling application sets the DWORD value to the number of bytes to be decrypted. Upon return, the DWORD value contains the number of bytes of the decrypted plaintext.
        if CryptDecrypt(hDecryptKey, 0, true, 0, @output[0] /*pbData*/, ResultLen) then
        begin
          log('CryptDecrypt OK',0);
          //SetLength(Result, ResultLen);
          result:=true;
        end
        else
        begin
          //NT_BAD_DATA (0x80090005)
          log('ResultLen:'+inttostr(ResultLen),0);
          if ResultLen >0 then result:=true else result:=false;
          log('CryptDecrypt NOT OK '+ IntTohex(GetLastError,4),0);
          log('DATA:'+BytetoAnsiString (output));
          Result := true;
        end;

        CryptDestroyKey(hDecryptKey);
      end;

      CryptDestroyKey(hKey);
    end;

    CryptReleaseContext(hCryptProvider, 0);
  end;
end;
}

function crypto_hkey(hProv:HCRYPTPROV; calgid:ALG_ID; key:LPCVOID; keyLen:DWORD; flags:DWORD; var hKey:HCRYPTKEY; var hSessionProv:HCRYPTPROV):boolean;
var
  status:BOOL {$ifdef fpc}=FALSE{$endif fpc};
  keyBlob:PGENERICKEY_BLOB;
  szBlob:DWORD;
  //
  temp:array of byte;
begin
        status:=false;
        szBlob := sizeof(GENERICKEY_BLOB) + keyLen;

        {
        log('sizeof(GENERICKEY_BLOB):'+inttostr(sizeof(GENERICKEY_BLOB)),0);
        log('keyLen:'+inttostr(keyLen),0);
        SetLength(temp,keyLen);
        CopyMemory(@temp[0],key,keyLen);
        log(ByteToHexaString (temp),0);
        }

	if(calgid <> CALG_3DES) then
	begin
          keyBlob:=Pointer(LocalAlloc(LPTR, szBlob));
		if(keyBlob <>nil) then
		begin
			keyBlob^.Header.bType := PLAINTEXTKEYBLOB;
			keyBlob^.Header.bVersion := CUR_BLOB_VERSION;
			keyBlob^.Header.reserved := 0;
			keyBlob^.Header.aiKeyAlg := calgid;
			keyBlob^.dwKeyLen := keyLen;
			//RtlCopyMemory((PBYTE) keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
                        CopyMemory(pointer(nativeuint(keyBlob) + sizeof(GENERICKEY_BLOB)),key,keyBlob^.dwKeyLen);
                        status := CryptImportKey(hProv, pbyte(keyBlob), szBlob, 0, flags, hKey);
			LocalFree(thandle(keyBlob));
		end;
	//}
	//else if(hSessionProv)
	//	status = kull_m_crypto_hkey_session(calgid, key, keyLen, flags, hKey, hSessionProv);
        //end;
        end;

	result:= status;
end;







function crypto_cipher_blocklen( hashId:ALG_ID):DWORD;
var
	len:DWORD {$ifdef fpc}=0{$endif fpc};
        dwSize:dword {$ifdef fpc}= sizeof(DWORD){$endif fpc};
	hProv:HCRYPTPROV;
	hKey:HCRYPTKEY;
begin
{$ifndef fpc}dwsize:=sizeof(DWORD);{$endif fpc}
	if CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
	begin
		if CryptGenKey(hProv, hashId, 0, hKey) then
		begin
			CryptGetKeyParam(hKey, KP_BLOCKLEN, @len, dwSize, 0);
			CryptDestroyKey(hKey);
		end;
		CryptReleaseContext(hProv, 0);
	end;
	result:= len div 8;
        log('crypto_cipher_blocklen:'+inttostr(result),0);
end;

function crypto_cipher_keylen( hashId:ALG_ID):dword;
var
	len:dword {$ifdef fpc}= 0{$endif fpc};
        dwSize:dword {$ifdef fpc}= sizeof(DWORD){$endif fpc};
	hProv:HCRYPTPROV;
	hKey:HCRYPTKEY;
begin
	if CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
	begin
        //log('CryptAcquireContext OK',0);
		if CryptGenKey(hProv, hashId, 0, hKey) then
		begin
                //log('CryptGenKey OK',0);
			if CryptGetKeyParam(hKey, KP_KEYLEN, @len, dwSize, 0)
                           then ; //log('CryptGetKeyParam OK',0);
			CryptDestroyKey(hKey);
		end;
		CryptReleaseContext(hProv, 0);
	end;
	result:= len div 8;
        log('crypto_cipher_keylen:'+inttostr(result),0);
end;

function crypto_hash_len( hashId:ALG_ID):dword;
var
	 len:DWORD {$ifdef fpc}= 0{$endif fpc};
	 hProv:HCRYPTPROV;
	 hHash:HCRYPTHASH;
begin
	if CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
	begin
		if CryptCreateHash(hProv, hashId, 0, 0, hHash) then
		begin
			CryptGetHashParam(hHash, HP_HASHVAL, nil, len, 0);
			CryptDestroyHash(hHash);
		end;
		CryptReleaseContext(hProv, 0);
	end;
	result:= len;
        log('crypto_hash_len:'+inttostr(result),0);
end;



function crypto_hash_hmac(calgid:DWORD; key:{LPCVOID}lpbyte;keyLen:DWORD; message:{LPCVOID}lpbyte; messageLen:DWORD; hash:LPVOID;hashWanted:DWORD ):boolean;
const
CRYPT_IPSEC_HMAC_KEY    =$00000100;  // CryptImportKey only

type

  HMAC_Info_ = record   //40 bytes ok in x64 vs 28 bytes in jwawincrypt
    HashAlgid: ALG_ID;
    pbInnerString: pointer;
    cbInnerString: DWORD;
    pbOuterString: pointer;
    cbOuterString: DWORD;
  end;

var
	 status:BOOL {$ifdef fpc}= FALSE{$endif fpc};
	 hashLen:DWORD;
	 hProv,hSessionProv:HCRYPTPROV;
	 hKey:HCRYPTKEY;
	 hHash:HCRYPTHASH;
	 HmacInfo:HMAC_Info_; // = (calgid, nil, 0, nil, 0);
         buffer:PBYTE;
         //
         temp:array of byte;
         w:array of widechar;
begin
  hSessionProv:=0;
  log('**** crypto_hash_hmac ****',0);
  //log('sizeof(HmacInfo):'+inttostr(sizeof(HmacInfo )),0);
  log('calgid:'+inttohex(calgid,sizeof(calgid)),0);
  log('keylen:'+inttostr(keylen),0);
  //
  {
  SetLength(temp,keylen);
  CopyMemory(@temp[0],key,keylen);
  log(ByteToHexaString (temp),0);
  }
  //
  log('messagelen:'+inttostr(messagelen),0);
  //
  {
  setlength(w,messagelen);
  copymemory(@w[0],message,messagelen);
  log(strpas(pwidechar(@w[0])),0);
  }
  //
  ZeroMemory(@HmacInfo,sizeof(HmacInfo ));
  HmacInfo.HashAlgid :=calgid ;
  HmacInfo.pbInnerString :=nil;
  HmacInfo.cbInnerString :=0;
  HmacInfo.pbOuterString :=nil;
  HmacInfo.cbOuterString :=0;
  //
  log('hashWanted:'+inttostr(hashWanted),0);

	if CryptAcquireContext(hProv, nil, nil, {PROV_RSA_FULL}PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
	begin
        log('CryptAcquireContext',0);
                //lets import our key=sha1 of widestring password
		if crypto_hkey(hProv, CALG_RC2, key, keyLen, CRYPT_IPSEC_HMAC_KEY, hKey,hSessionProv ) then
                //if 1=1 then
                begin
                log('crypto_hkey',0);
			if CryptCreateHash(hProv, CALG_HMAC, hKey, 0, hHash) then
			begin
                        log('CryptCreateHash',0);
				if CryptSetHashParam(hHash, HP_HMAC_INFO, @HmacInfo, 0) then
                                begin
                                log('CryptSetHashParam',0);
					if CryptHashData(hHash, message, messageLen, 0) then
                                        begin
                                        log('CryptHashData',0);
						if CryptGetHashParam(hHash, HP_HASHVAL, nil, hashLen, 0) then
						begin
                                                log('CryptGetHashParam',0);
                                                log('hashLen:'+inttostr(hashLen),0);
                                                        buffer:=Pointer(LocalAlloc(LPTR, hashLen));
							if buffer <>nil then
							begin
								status := CryptGetHashParam(hHash, HP_HASHVAL, buffer, hashLen, 0);
                                                                CopyMemory(hash, buffer, min(hashLen, hashWanted));
                                                                //SetLength(temp,min(hashLen, hashWanted));
                                                                //CopyMemory(@temp[0],buffer,min(hashLen, hashWanted));
                                                                //log(ByteToHexaString (temp),0);
                                                                LocalFree(thandle(buffer));
							end; //if buffer
						end;//CryptGetHashParam
						CryptDestroyHash(hHash);
                                                end; //CryptHashData
                                                end //CryptSetHashParam
                                                else log('CryptSetHashParam failed:'+inttostr(getlasterror),0);
			end; //CryptCreateHash
			CryptDestroyKey(hKey);
		end; //kull_m_crypto_hkey
		CryptReleaseContext(hProv, 0);
	end; //CryptAcquireContext
	result:= status;
        log('**** crypto_hash_hmac:'+BoolToStr (status)+' ****');
end;

//hardSecretBlob = PNT6_HARD_SECRET
function lsadump_sec_aes256(var hardSecretBlob:tbytes; hardSecretBlobSize:dword;lsaKeysStream:pointer;sysKey:pointer):boolean;
const
  CALG_SHA_256 = $0000800c;
  CALG_SHA_384 = $0000800d;
  CALG_SHA_512 = $0000800e;
  LAZY_NT6_IV_SIZE=32;
  AES_256_KEY_SIZE=256 div 8;
  //CALG_SHA_256 = (ALG_CLASS_HASH or ALG_TYPE_ANY or 12);
  //CALG_AES_128 = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or 14);
  //CALG_AES_192 = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or 15);
  //CALG_AES_256 = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or 16);

var
 hContext:HCRYPTPROV;
 hHash:HCRYPTHASH;
 hKey:HCRYPTKEY;
 pKey:PBYTE {$ifdef fpc}= NIL{$endif fpc};
 i, szNeeded:DWORD;
 keyBuffer:array [0..AES_256_KEY_SIZE-1] of byte;
 status:BOOL {$ifdef fpc}= FALSE{$endif fpc};
 hSessionProv:HCRYPTPROV{$ifdef fpc}= 0{$endif fpc};
begin
  status:=false;
log('**** lsadump_sec_aes256 ****');

if syskey<>nil then
   begin
   pKey := sysKey;
   szNeeded := 16; //SYSKEY_LENGTH;
   end;

if lsaKeysStream <>nil then
   begin
   log('KeyId:'+GUIDToString(PNT6_SYSTEM_KEY(lsaKeysStream)^.KeyId )) ;
   szNeeded:=PNT6_SYSTEM_KEY(lsaKeysStream)^.KeySize;
   {$ifdef fpc}pkey:=lsaKeysStream + sizeof(dword)*2+sizeof(guid);{$endif fpc};
   {$ifndef fpc}pkey:=pointer(nativeuint(lsaKeysStream) + sizeof(dword)*2+sizeof(guid));{$endif fpc};
   end;

log('pkey:'+ByteToHexaString (pkey,szNeeded));

  if(CryptAcquireContext(hContext, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) then
		begin
                log('CryptAcquireContext OK');
			if(CryptCreateHash(hContext, CALG_SHA_256, 0, 0, hHash)) then
			begin
                        log('CryptCreateHash OK');
				CryptHashData(hHash, pKey, szNeeded, 0);
				for i:= 0 to 1000-1 do	CryptHashData(hHash, @PNT6_HARD_SECRET(@hardSecretBlob[0])^.lazyiv[0], LAZY_NT6_IV_SIZE, 0);

				szNeeded := sizeof(keyBuffer);
				if(CryptGetHashParam(hHash, HP_HASHVAL, @keyBuffer[0], szNeeded, 0)) then
				begin
                                log('CryptGetHashParam OK');
                                log('Hash:'+ByteToHexaString(@keyBuffer[0],szNeeded) );
					if (crypto_hkey(hContext, CALG_AES_256, @keyBuffer[0], sizeof(keyBuffer), 0, hKey, hSessionProv)) then
                                        //if 1=1 then
                                        begin
                                        log('crypto_hkey OK');
						i := CRYPT_MODE_ECB;
						if(CryptSetKeyParam(hKey, KP_MODE, @i, 0)) then
						begin
                                                log('CryptSetKeyParam OK');
                                                	szNeeded := hardSecretBlobSize - PtrUInt(@NT6_HARD_SECRET(Nil^).Secret); //FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
                                                        log('hardSecretBlobSize:'+inttostr(hardSecretBlobSize));
                                                        log('szNeeded:'+inttostr(szNeeded));
                                                        log('encryptedSecret:'+ByteToHexaString(@hardSecretBlob[PtrUInt(@NT6_HARD_SECRET(Nil^).Secret)],szNeeded ));
                                                        status := CryptDecrypt(hKey, 0, FALSE, 0, @hardSecretBlob[PtrUInt(@NT6_HARD_SECRET(Nil^).Secret)], szNeeded);
							if(status=false)
                                                           then log('CryptDecrypt not ok')
                                                           else log('decoded:'+ByteToHexaString(@hardSecretBlob[PtrUInt(@NT6_HARD_SECRET(Nil^).Secret)],szNeeded ));
						end
						else log('CryptSetKeyParam not ok');
						CryptDestroyKey(hKey);
					end
					else log('kull_m_crypto_hkey not ok');
				end;
				CryptDestroyHash(hHash);
			end;
			CryptReleaseContext(hContext, 0);
		end;
  result:=status;

end;

//------------------------------------------------------------------------------
{
function _AES128ECB_Decrypt(const Value: RawByteString; const Key: RawByteString): RawByteString;
var
  pbData: PByte;
  hCryptProvider: HCRYPTPROV;
  KeyBlob: packed record
    Header: BLOBHEADER;
    Size: DWORD;
    Data: array[0..15] of Byte;
  end;
  hKey, hDecryptKey: HCRYPTKEY;
  dwKeyCypherMode: DWORD;
  ResultLen: DWORD;
const
  PROV_RSA_AES = 24;
  CALG_AES_128 = $0000660e;
  AESFinal = True;
begin
  Result := '';
  // MS_ENH_RSA_AES_PROV
  if CryptAcquireContext(hCryptProvider, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  begin
    KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
    keyBlob.Header.bVersion := CUR_BLOB_VERSION;
    keyBlob.Header.reserved := 0;
    keyBlob.Header.aiKeyAlg := CALG_AES_128;
    keyBlob.Size := Length(Key);
    CopyMemory(@keyBlob.Data[0], @Key[1], keyBlob.Size);

    if CryptImportKey(hCryptProvider, @KeyBlob, SizeOf(KeyBlob), 0, 0, hKey) then
    begin
      if CryptDuplicateKey(hKey, nil, 0, hDecryptKey) then
      begin
        dwKeyCypherMode := CRYPT_MODE_ECB; //CRYPT_MODE_CBC
        CryptSetKeyParam(hDecryptKey, KP_MODE, @dwKeyCypherMode, 0);

        Result := Value;
        pbData := Pointer(Result);
        ResultLen := Length(Result);

        // the calling application sets the DWORD value to the number of bytes to be decrypted. Upon return, the DWORD value contains the number of bytes of the decrypted plaintext.
        if CryptDecrypt(hDecryptKey, 0, AESFinal, 0, pbData, ResultLen) then
        begin
          SetLength(Result, ResultLen);
        end
        else
        begin
          Result := '';
        end;

        CryptDestroyKey(hDecryptKey);
      end;

      CryptDestroyKey(hKey);
    end;

    CryptReleaseContext(hCryptProvider, 0);
  end;
end;
}

//------------------------------------------------------------------------------
{
function _Encrypt(algid:longword;const Value: RawByteString; const Key: RawByteString): RawByteString;
var
  pbData: PByte;
  hCryptProvider: HCRYPTPROV;
  KeyBlob: packed record
    Header: BLOBHEADER;
    Size: DWORD;
    Data: array[0..15] of Byte;
  end;
  hKey, hEncryptKey: HCRYPTKEY;
  dwKeyCypherMode: DWORD;
  InputLen, ResultLen: DWORD;
const
  PROV_RSA_AES = 24;
  AESFinal = True;
begin
  Result := '';
  // MS_ENH_RSA_AES_PROV
  if CryptAcquireContext(hCryptProvider, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  begin
    log('CryptAcquireContext OK');
    KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
    keyBlob.Header.bVersion := CUR_BLOB_VERSION;
    keyBlob.Header.reserved := 0;
    keyBlob.Header.aiKeyAlg := algid; //CALG_AES_128
    keyBlob.Size := Length(Key);
    CopyMemory(@keyBlob.Data[0], @Key[1], keyBlob.Size);

    if CryptImportKey(hCryptProvider, @KeyBlob, SizeOf(KeyBlob), 0, 0, hKey) then
    begin
      log('CryptImportKey OK');
      if CryptDuplicateKey(hKey, nil, 0, hEncryptKey) then
      begin
        log('CryptDuplicateKey OK');
        dwKeyCypherMode := CRYPT_MODE_CBC;
        CryptSetKeyParam(hEncryptKey, KP_MODE, @dwKeyCypherMode, 0);

        InputLen := Length(Value);
        ResultLen := InputLen;

        // nil dans pbData => If this parameter contains NULL, this function will calculate the required size for the ciphertext and place that in the value pointed to by the pdwDataLen parameter.
        if CryptEncrypt(hEncryptKey, 0, AESFinal, 0, nil, ResultLen, 0) then
        begin
          log('CryptEncrypt OK');
          SetLength(Result, ResultLen);
          Move(Value[1], Result[1], Length(Value));
          pbData := Pointer(PAnsiChar(Result));
          if not CryptEncrypt(hEncryptKey, 0, AESFinal, 0, pbData, InputLen, ResultLen) then
          begin
            Result := '';

            OutputDebugCRYPT('TSLTAES128ECB.Encrypt ' + IntToStr(GetLastError()));

          end;
        end
        else
        begin
          Result := '';

          OutputDebugCRYPT('TSLTAES128ECB.Pre-Encrypt ' + IntToStr(GetLastError()));

        end;

        CryptDestroyKey(hEncryptKey);
      end;

      CryptDestroyKey(hKey);
    end;

    CryptReleaseContext(hCryptProvider, 0);
  end;
end;
}

 //beware of stream cipher vs block cipher
 function EnCryptDecrypt(algid:dword;hashid:dword;CRYPT_MODE:dword;const key: tbytes;var buffer:tbytes;const decrypt:boolean=false):boolean;
 const
   CRYPT_EXPORTABLE = $00000001;
   CRYPT_NO_SALT    = $10;
   AES_KEY_SIZE =16; //also AES_BLOCK_SIZE  ? look at https://stackoverflow.com/questions/9091108/cryptencrypt-aes-256-fails-at-encrypting-last-block
 var
  hProv: HCRYPTPROV;
  hash: HCRYPTHASH{$ifdef fpc}=0{$endif fpc};
  hkey: HCRYPTKEY;

  ret:boolean{$ifdef fpc}=false{$endif fpc};
  datalen,buflen: dWord;
  dwKeyCypherMode,dwsize,dwBLOCKLEN,dwKEYLEN,hash_len: DWORD;
  hash_buffer,data:tbytes;
  MS_ENH_RSA_AES_PROV:pchar{$ifdef fpc}='Microsoft Enhanced RSA and AES Cryptographic Provider'+#0{$endif fpc};
  //
  KeyBlob:  packed record
      Header: BLOBHEADER;  //8
      Size: DWORD;    //4
      Data: array[0..127] of Byte; //16
    end;
  //
begin
{$ifndef fpc}
MS_ENH_RSA_AES_PROV:='Microsoft Enhanced RSA and AES Cryptographic Provider'+#0;
{$endif fpc};
  result:=false;
  {
  if decrypt=false
     then log('buffer:'+BytetoAnsiString(buffer))
     else log('buffer:'+ByteToHexaString (buffer));
  log('key:'+BytetoAnsiString(key));
  }
  log('ALG_ID:'+inttohex(algid,sizeof(algid )));
  log('buffer length:'+inttostr(length(buffer)));
  log('key length:'+inttostr(length(key) )); // The secret key must equal the size of the key.
  {get context for crypt default provider}
  //https://docs.microsoft.com/fr-fr/windows/win32/seccrypto/prov-rsa-aes?redirectedfrom=MSDN
  //if fail then try again with CRYPT_NEWKEYSET
  //if CryptAcquireContext(hProv, nil, nil,  PROV_RSA_FULL, 0{CRYPT_VERIFYCONTEXT}) then
  if CryptAcquireContext(hProv, nil, MS_ENH_RSA_AES_PROV, PROV_RSA_AES , CRYPT_VERIFYCONTEXT) then
  //if CryptAcquireContext(hProv, nil, MS_ENHANCED_PROV, PROV_RSA_FULL,CRYPT_VERIFYCONTEXT) then
  begin
  //create hash-object ... or import key
  log('CryptAcquireContext');
  //if CryptCreateHash(hProv, hashid, 0, 0, hash) then
  if 1=1 then
  begin
  //log('CryptCreateHash');
  //get hash from password ... or import key
  //if CryptHashData(hash, @key[0], Length(key) , 0) then
  if 1=1 then
  begin
  //log('CryptHashData');
  hash_len:=16;
  setlength(hash_buffer,hash_len );
  if hash<>0 then if CryptGetHashParam(hash, HP_HASHVAL, @hash_buffer[0], hash_len, 0)
     then log('CryptGetHashParam OK:'+ByteToHexaString (hash_buffer) )
     else log('CryptGetHashParam NOT OK');

  //https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
  //This function is the same as CryptGenKey, except that the generated session keys are derived from base data instead of being random
  //cryptgenkey to retrieve keylen and blocklen?
  //we could use CryptImportKey as well with the key handled externally rather that derived from a hash
  //create key from hash
  //ret:=CryptDeriveKey(hProv, algid, hash, 0 or CRYPT_EXPORTABLE{CRYPT_NO_SALT}, hkey);
  //import key
  KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
  keyBlob.Header.bVersion := CUR_BLOB_VERSION;
  keyBlob.Header.reserved := 0;
  keyBlob.Header.aiKeyAlg := algid ;
  keyBlob.Size := Length(Key);
  CopyMemory(@keyBlob.Data[0], @Key[0], keyBlob.Size);
  //log('KeyBlob:'+inttostr(SizeOf(KeyBlob)));
  //importkey is more convenient as we can import any key but some algos dont work for now like 3des
  ret:=CryptImportKey(hProv, @KeyBlob, SizeOf(BLOBHEADER )+sizeof(dword)+length(key), 0, 0, hKey);
  if ret=true then
  begin
  //log('CryptDeriveKey');
  log('CryptImportKey');
  {
  AES is a block cipher, and like all block ciphers it can be used in one of several modes,
  such as ECB, CBC, OCB, CTR.
  Only the first of these modes - ECB, or electronic code book, which is the fundamental block encryption mode -
  allows a single block of output to result from the encryption of a single input block.
  The others are geared towards encoding multiple blocks of input data,
  and involve additional data (the IV) which means the output is longer than the input.
  }
  //below only applies to block ciphers
  //An initialization vector is required if using CBC mode
  if 1=1 then
  begin
  dwKeyCypherMode := crypt_mode;    //dcrypt2 default is CBC //ms default is CRYPT_MODE_CBC
  //log('KP_MODE:'+inttostr(dwKeyCypherMode));
  if CryptSetKeyParam(hkey, KP_MODE, @dwKeyCypherMode, 0)=true
     then log('CryptSetKeyParam KP_MODE OK,'+inttostr(dwKeyCypherMode) )
     else log('CryptSetKeyParam KP_MODE NOT OK,'+inttostr(getlasterror));
  end;
  //
  //look at KP_PADDING, KP_ALGID
  //
  dwsize:=sizeof(dwBLOCKLEN);
  dwBLOCKLEN:=0;
  //KP_BLOCKLEN size in bits
  //we get the block length as we can only encrypt up to that size, per pass
  if CryptGetKeyParam (hkey,KP_BLOCKLEN ,@dwBLOCKLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_BLOCKLEN OK,'+inttostr(dwBLOCKLEN div 8))
     else log('CryptGetKeyParam KP_BLOCKLEN NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_MODE ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_MODE OK,'+inttostr(dwKEYLEN ))
     else log('CryptGetKeyParam KP_MODE NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_KEYLEN ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_KEYLEN OK,'+inttostr(dwKEYLEN div 8))
     else log('CryptGetKeyParam KP_KEYLEN NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_EFFECTIVE_KEYLEN ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_EFFECTIVE_KEYLEN OK,'+inttostr(dwKEYLEN div 8))
     else log('CryptGetKeyParam KP_EFFECTIVE_KEYLEN NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_PADDING ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_PADDING OK,'+inttostr(dwKEYLEN ))
     else log('CryptGetKeyParam KP_PADDING NOT OK');
  {
  dwKEYLEN:=PKCS5_PADDING; //only one supported...
  if CryptSetKeyParam(hkey, KP_PADDING, @dwKEYLEN, 0)=true
     then log('CryptSetKeyParam KP_PADDING OK')
     else log('CryptSetKeyParam KP_PADDING NOT OK,'+inttostr(getlasterror));
  }
  {destroy hash-object}
  if hash<>0 then
     begin
     CryptDestroyHash(hash);
     log('CryptDestroyHash');
     end;

     buflen := length(buffer);

        if decrypt =false then
        begin
        datalen:=buflen;
        if CryptEncrypt(hkey, 0, true, 0, nil, datalen, 0)
           then log('CryptEncrypt OK')
           else log('CryptEncrypt:NOT OK'+inttostr(getlasterror));

        //lets create a buffer big enough to hold the encrypted data
        if dwBLOCKLEN<>0 then datalen:=((length(buffer) + dwBLOCKLEN -1) div dwBLOCKLEN) *dwBLOCKLEN ;
        log('datalen:'+inttostr(datalen));
        setlength(data,datalen);
        ZeroMemory(@data[0],datalen);
        copymemory(@data[0],@buffer[0],buflen);

        {crypt buffer}
        //https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencrypt
        result:= CryptEncrypt(hkey, 0, true, 0, @data[0],  buflen,datalen);
        if result
           then log('CryptEncrypt:'+inttostr(buflen))
           else log('CryptEncrypt:NOT OK,'+inttostr(buflen)+','+inttostr(getlasterror));

        //lets push the encrypted buffer back
        if result=true then
           begin
           setlength(buffer,buflen);
           ZeroMemory(@buffer[0],buflen);
           copymemory(@buffer[0],@data[0],buflen);
           end;
        end
        else //if decrypt =false then
        begin
        {decrypt buffer}
        datalen:=buflen*2;
        setlength(data,datalen);
        ZeroMemory(@data[0],datalen);
        copymemory(@data[0],@buffer[0],buflen);
        result:=CryptDecrypt(hkey, 0, true, 0, @data[0], buflen);
          if result
             then log('CryptDecrypt:'+inttostr(buflen))
             else log('CryptDecrypt:NOT OK,'+inttostr(buflen)+','+inttostr(getlasterror));
        //lets push the decrypted buffer back
        if result=true then
           begin
           setlength(buffer,buflen);
           copymemory(@buffer[0],@data[0],buflen);
           end;

        end;
  end // if CryptDeriveKey
  else log('CryptDeriveKey NOT OK,'+inttohex(getlasterror,4));
  //0x80090008 | 2148073480 NTE_BAD_ALGID
  //0x80090005 bad data
  //0x80090004(NTE_BAD_LEN)
  //0x80090009 NTE_BAD_FLAGS
  end //if CryptHashData
  else log('CryptHashData NOT OK');
  end //if CryptCreateHash
  else log('CryptCreateHash NOT OK');
  {release the context for crypt default provider}
  CryptReleaseContext(hProv, 0);
  log('CryptReleaseContext');

  end //if CryptAcquireContext
  else log('CryptAcquireContext NOT OK,'+inttostr(getlasterror));
end;
//***********************************************************

{
procedure _doSomeEncryption();
var
  HASHOBJ: HCRYPTHASH;
  hProv: HCRYPTPROV;
  bHash: tBytes;
  dwHashBytes: DWORD;
begin
  if not CryptAcquireContext(hProv, nil, nil, PROV_RSA_FULL , CRYPT_VERIFYCONTEXT) then
    raiseLastOsError;

  if not CryptCreateHash(hProv, CALG_SHA, 0, 0, HASHOBJ) then
    raiseLastOsError;

  // Your encrypt stuff here
  //CryptEncrypt(yourHKey, HASHOBJ, ...) //

  setLength(bHash, 255);  // Allocate the buffer
  if CryptGetHashParam(HASHOBJ, HP_HASHVAL, @bHash[0], dwHashBytes, 0) then
  begin
    setLength(bHash, dwHashBytes);  // bHash now contains the hash bytes
  end
  else
    setLength(bHash, 0);

  //  Release HASHOBJ
  CryptDestroyHash(HASHOBJ);

  //  Release Provider Context
  CryptReleaseContext(hProv, 0);

end;
}

//***************************************************************
{
function _Hashhmacsha1(const Key, Value: AnsiString): AnsiString;
const
  KEY_LEN_MAX = 16;
var
  hCryptProvider: HCRYPTPROV;
  hHash: HCRYPTHASH;
  hKey: HCRYPTKEY;
  bHash: array[0..$7F] of Byte;
  dwHashLen: dWord;
  i: Integer;

  hPubKey : HCRYPTKey;
  hHmacHash: HCRYPTHASH;
  bHmacHash: array[0..$7F] of Byte;
  dwHmacHashLen: dWord;
  hmac_info_ : HMAC_INFO;

  keyBlob: record
    keyHeader: BLOBHEADER;
    keySize: DWORD;
    keyData: array[0..KEY_LEN_MAX-1] of Byte;
  end;
  keyLen : INTEGER;
begin
  dwHashLen := 32;
  dwHmacHashLen := 32;
  //get context for crypt default provider
  if CryptAcquireContext(hCryptProvider, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
  begin
    //create hash-object MD5
  log('CryptAcquireContext',0);
    if CryptCreateHash(hCryptProvider, CALG_SHA1, 0, 0, hHash) then
    begin
    log('CryptCreateHash',0);
      //get hash from password
      if CryptHashData(hHash, PByte(Key), Length(Key), 0) then
      begin
      log('CryptHashData',0);
        // hHash is now a hash of the provided key, (SHA1)
        // Now we derive a key for it
        hPubKey := 0;

        FillChar(keyBlob, SizeOf(keyBlob), 0);
        keyBlob.keyHeader.bType := PLAINTEXTKEYBLOB;
        keyBlob.keyHeader.bVersion := CUR_BLOB_VERSION;
        keyBlob.keyHeader.aiKeyAlg := CALG_RC4;
        KeyBlob.keySize := KEY_LEN_MAX;

        if(Length(key) < (KEY_LEN_MAX))then
          KeyLen := Length(key)
        else
          KeyLen := KEY_LEN_MAX;
        Move(Key[1], KeyBlob.keyData[0], KeyLen );

        if CryptImportKey(hCryptProvider, @keyBlob, SizeOf(KeyBlob), hPubKey, 0, hKey) then
        begin
        log('CryptImportKey',0);
          //hkey now holds our key. So we have do the whole thing over again
          ZeroMemory( @hmac_info_, SizeOf(hmac_info) );
          hmac_info_.HashAlgid := CALG_SHA1;
          if CryptCreateHash(hCryptProvider, CALG_HMAC, hKey, 0, hHmacHash) then
          begin
          log('CryptCreateHash',0);
              if CryptSetHashParam( hHmacHash, HP_HMAC_INFO, @hmac_info_, 0) then
              begin
              log('CryptSetHashParam',0);
                if CryptHashData(hHmacHash, @Value[1], Length(Value), 0) then
                begin
                log('CryptHashData',0);
                  if CryptGetHashParam(hHmacHash, HP_HASHVAL, @bHmacHash[0], dwHmacHashLen, 0) then
                  begin
                  log('CryptGetHashParam',0);
                    for i := 0 to dwHmacHashLen-1 do
                      Result := Result + IntToHex(bHmacHash[i], 2);
                  end
                  else
                   WriteLn( 'CryptGetHashParam ERROR --> ' + SysErrorMessage(GetLastError)) ;
                end
                else
                  WriteLn( 'CryptHashData ERROR --> ' + SysErrorMessage(GetLastError)) ;
                //destroy hash-object
                CryptDestroyHash(hHmacHash);
                CryptDestroyKey(hKey);
              end
              else
                WriteLn( 'CryptSetHashParam ERROR --> ' + SysErrorMessage(GetLastError)) ;

          end
          else
            WriteLn( 'CryptCreateHash ERROR --> ' + SysErrorMessage(GetLastError)) ;
        end
        else
          WriteLn( 'CryptDeriveKey ERROR --> ' + SysErrorMessage(GetLastError)) ;

      end;
      //destroy hash-object
      CryptDestroyHash(hHash);
    end;
    //release the context for crypt default provider
    CryptReleaseContext(hCryptProvider, 0);
  end;
  Result := AnsiLowerCase(Result);
end;
}

function initAPI:boolean;
  var
  lib:hmodule=0;
  lib2:hmodule=0;
  begin
  //writeln('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('crypt32.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('crypt32.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary crypt32.dll');
    exit;
    end;
  CryptUnprotectData:=getProcAddress(lib,'CryptUnprotectData');
  CryptProtectData:=getProcAddress(lib,'CryptProtectData');
  //
  lib2:=loadlibrary('bcrypt.dll');
  BCryptOpenAlgorithmProvider:=getProcAddress(lib2,'BCryptOpenAlgorithmProvider');
  BCryptSetProperty:=getProcAddress(lib2,'BCryptSetProperty');
  BCryptGenerateSymmetricKey:=getProcAddress(lib2,'BCryptGenerateSymmetricKey');
  BCryptEncrypt:=getProcAddress(lib2,'BCryptEncrypt');
  BCryptDecrypt:=getProcAddress(lib2,'BCryptDecrypt');
  //
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


