unit udpapi;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,JwaWinCrypt,utils,ucryptoapi;

function dpapi_unprotect_credhist_entry_with_shaDerivedkey( entry:tDPAPI_CREDHIST_ENTRY; shaDerivedkey:LPCVOID; shaDerivedkeyLen: DWORD; md4hash:PVOID; sha1hash:PVOID):boolean;
function dpapi_unprotect_masterkey_with_shaDerivedkey(masterkey:tmasterkey;  shaDerivedkey:LPCVOID;shaDerivedkeyLen:DWORD; var output:PVOID;var outputLen:DWORD):boolean;
function dpapi_unprotect_blob(blob:PDPAPI_BLOB;  masterkey:LPCVOID; masterkeyLen:DWORD; entropy:LPCVOID;  entropyLen:DWORD; password:LPCWSTR; var dataOut:LPVOID; var dataOutLen:DWORD):boolean;

//var
 //https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory/
 //CryptUnprotectMemory:function(pDataIn:LPVOID;cbDataIn:DWORD;dwFlags:DWORD): BOOL; stdcall;
 //CryptProtectMemory:function(pDataIn:LPVOID;cbDataIn:DWORD;dwFlags:DWORD): BOOL; stdcall;

implementation



//const   apilib = 'dpapi.dll';

var
 HApi: THandle = 0;

function string_getRandomGUID:pwidechar;
var
	 guid:tGUID;
begin
  CreateGuid(gUid);
  result:=pwidechar(widestring(GUIDToString(guid)));
end;

function crypto_close_hprov_delete_container( hProv:HCRYPTPROV):boolean;
var

	 status:BOOL = FALSE;
	 provtype:DWORD=0;
         szLen:dword = 0;
	 container, provider:PSTR;
begin
	if CryptGetProvParam(hProv, PP_CONTAINER, nil, szLen, 0) then
	begin
        container := PSTR (LocalAlloc(LPTR, szLen));
		if container<>nil then
		begin
			if CryptGetProvParam(hProv, PP_CONTAINER,  lpbyte(container), szLen, 0) then
			begin
				if CryptGetProvParam(hProv, PP_NAME, nil, szLen, 0) then
				begin
                                provider := PSTR(LocalAlloc(LPTR, szLen));
					if provider<>nil then
					begin
						if CryptGetProvParam(hProv, PP_NAME, LPBYTE(provider), szLen, 0) then
						begin
							szLen := sizeof(DWORD);
							if CryptGetProvParam(hProv, PP_PROVTYPE, LPBYTE(provtype), szLen, 0) then
							begin
								CryptReleaseContext(hProv, 0);
								status := CryptAcquireContextA(hProv, container, provider, provtype, CRYPT_DELETEKEYSET);
							end;
						end;
						LocalFree(thandle(provider));
					end;
				end;
				LocalFree(thandle(container));
			end;
		end;
	end;
	if not status then ;
		//PRINT_ERROR_AUTO(L"CryptGetProvParam/CryptAcquireContextA");
	result:= status;
end;



function crypto_hkey_session( calgid:ALG_ID;  key:LPCVOID;  keyLen:DWORD;  flags:DWORD; var hSessionKey:HCRYPTKEY; var hSessionProv:HCRYPTPROV):boolean;
var
	 status:BOOL = FALSE;
	 keyblob, pbSessionBlob, ptr:PBYTE;
	 dwkeyblob, dwLen, i:DWORD;
	 container:pointer; //PWSTR;
	 hPrivateKey:HCRYPTKEY;
         //
         tmp:tbytes;
begin
log('**** crypto_hkey_session ****',0);
log('calgid:'+inttohex(calgid,sizeof(calgid)),0);
log('keyLen:'+inttostr(keyLen),0);
        container := string_getRandomGUID;
	if (container <>nil) then
	begin
        log('container ok',0);
		if CryptAcquireContextW(hSessionProv, container, nil, PROV_RSA_AES, CRYPT_NEWKEYSET) then
		begin
                log('CryptAcquireContext ok',0);
			hPrivateKey := 0;
			if CryptGenKey(hSessionProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE or RSA1024BIT_KEY, hPrivateKey) then // 1024
			begin
                        log('CryptGenKey ok',0);
				if CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, nil, dwkeyblob) then
				begin
                                log('CryptExportKey ok',0);
                                keyblob := LPBYTE(LocalAlloc(LPTR, dwkeyblob));
					if keyblob<>nil then
					begin
						if CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, dwkeyblob) then
						begin
                                                log('CryptExportKey ok',0);
							CryptDestroyKey(hPrivateKey);
							hPrivateKey := 0;

							dwLen := PRSAPUBKEY (nativeuint(keyblob) + sizeof(PUBLICKEYSTRUC))^.bitlen  div 8;
							PRSAPUBKEY (nativeuint(keyblob) + sizeof(PUBLICKEYSTRUC))^.pubexp := 1;
							ptr := pointer(nativeuint(keyblob) + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY));

							ptr += 2 * dwLen; // Skip pubexp, modulus, prime1, prime2
							ptr^ := 1; // Convert exponent1 to 1
							ZeroMemory(ptr + 1, dwLen div 2 - 1);
							ptr += dwLen div 2; // Skip exponent1
							ptr^ := 1; // Convert exponent2 to 1
							ZeroMemory(ptr + 1, dwLen div 2 - 1);
							ptr += dwLen; // Skip exponent2, coefficient
							ptr^ := 1; // Convert privateExponent to 1
							ZeroMemory(ptr + 1, (dwLen div 2) - 1);

							if CryptImportKey(hSessionProv, keyblob, dwkeyblob, 0, 0, hPrivateKey) then
							begin
                                                        log('CryptImportKey ok',0);
								dwkeyblob := (1024 div 8) + sizeof(ALG_ID) + sizeof(BLOBHEADER); // 1024
                                                                pbSessionBlob := LPBYTE(LocalAlloc(LPTR, dwkeyblob));
                                                                if pbSessionBlob<>nil then
								begin
									PBLOBHEADER(pbSessionBlob)^.bType := SIMPLEBLOB;
									PBLOBHEADER(pbSessionBlob)^.bVersion := CUR_BLOB_VERSION;
									PBLOBHEADER(pbSessionBlob)^.reserved := 0;
									PBLOBHEADER(pbSessionBlob)^.aiKeyAlg := calgid;
                                                                        //log('PBLOBHEADER ok',0);
                                                                        ptr := pbSessionBlob + sizeof(BLOBHEADER);
                                                                        //log(inttohex(nativeuint(ptr),sizeof(ptr)));
									//*(ALG_ID *) ptr = CALG_RSA_KEYX;
                                                                        pdword(ptr)^ := CALG_RSA_KEYX;
									ptr += sizeof(ALG_ID);
                                                                        //log(inttohex(nativeuint(ptr),sizeof(ptr)));
                                                                        log('ptr ok',0);
                                                                        log('keylen:'+inttostr(keyLen));
									for i := 0 to keyLen-1 do
                                                                            ptr[i] := PBYTE(key)[keyLen - i - 1];
                                                                            //copymemory(ptr+i,key+(keyLen - i - 1),1);
                                                                        log('ptr ok',0);
                                                                        ptr += (keyLen + 1);
                                                                        log('ptr ok',0);
                                                                        log('dwkeyblob:'+inttostr(dwkeyblob));
									for i := 0 to dwkeyblob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + keyLen + 3)-1 do if ptr[i] = 0 then ptr[i] := $42;
									pbSessionBlob[dwkeyblob - 2] := 2;
                                                                        //
                                                                        SetLength(tmp,dwkeyblob);
                                                                        CopyMemory (@tmp[0],pbSessionBlob ,dwkeyblob);
                                                                        log('pbSessionBlob:'+ByteToHexaString (tmp),0);
                                                                        //
									status := CryptImportKey(hSessionProv, pbSessionBlob, dwkeyblob, hPrivateKey, flags, hSessionKey);
                                                                        log('CryptImportKey ok',0);
                                                                        log('status:'+BoolToStr (status));
                                                                        LocalFree(thandle(pbSessionBlob));
								end;
							end;
						end;
						LocalFree(thandle(keyblob));
					end;
				end;
			end;
			if (hPrivateKey<>0) then CryptDestroyKey(hPrivateKey);
			if (not status) then crypto_close_hprov_delete_container(hSessionProv);
		end;
		LocalFree(thandle(container));
	end;
	result:= status;
        log('**** crypto_hkey_session:'+BoolToStr (status)+' ****');
end;


function dpapi_hmac_sha1_incorrect(key:LPCVOID;  keyLen:DWORD;  salt:LPCVOID;  saltLen:DWORD;  entropy:LPCVOID;  entropyLen:DWORD;  data:LPCVOID;  dataLen:DWORD;  outKey:LPVOID):boolean;
var
	status:BOOL = FALSE;
	ipad:array [0..63] of byte;
        opad:array [0..63] of byte;
        hash:array [0..SHA_DIGEST_LENGTH-1] of byte;
        bufferI, bufferO:pbyte;
	i:DWORD;
begin
  //RtlFillMemory(ipad, sizeof(ipad), '6');
  FillByte(ipad,sizeof(ipad),ord('6'));
  //RtlFillMemory(opad, sizeof(opad), '\\');
  FillByte(opad,sizeof(opad),ord('\'));

        for i := 0 to keyLen-1 do
	begin
		ipad[i] := ipad[i] xor PBYTE(key)[i];
		opad[i] := opad[i] xor PBYTE(key)[i];
	end;
        bufferI := PBYTE(LocalAlloc(LPTR, sizeof(ipad) + saltLen));
	if bufferI<>nil then
	begin
		//RtlCopyMemory(bufferI, ipad, sizeof(ipad));
                CopyMemory(bufferI, @ipad[0], sizeof(ipad));
		//RtlCopyMemory(bufferI + sizeof(ipad), salt, saltLen);
                CopyMemory(bufferI + sizeof(ipad), salt, saltLen);
		if crypto_hash(CALG_SHA1, bufferI, sizeof(ipad) + saltLen, @hash[0], SHA_DIGEST_LENGTH) then
		begin
                bufferO := PBYTE(LocalAlloc(LPTR, sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen + dataLen));
			if bufferO<>nil then
			begin
				//RtlCopyMemory(bufferO, opad, sizeof(opad));
                                CopyMemory(bufferO, @opad[0], sizeof(opad));
				//RtlCopyMemory(bufferO + sizeof(opad), hash, SHA_DIGEST_LENGTH);
                                CopyMemory(bufferO + sizeof(opad), @hash[0], SHA_DIGEST_LENGTH);
				if ((entropy<>nil) and (entropyLen>0)) then
					//RtlCopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH, entropy, entropyLen);
                                        CopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH, entropy, entropyLen);
				if ((data<>nil) and (dataLen>0)) then
					//RtlCopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen, data, dataLen);
                                        CopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen, data, dataLen);

				status := crypto_hash(CALG_SHA1, bufferO, sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen + dataLen, outKey, SHA_DIGEST_LENGTH);
				LocalFree(thandle(bufferO));
			end;
		end;
		LocalFree(thandle(bufferI));
	end;
	result:= status;
end;

function dpapi_sessionkey(masterkey:LPCVOID; masterkeyLen:DWORD; salt:LPCVOID;  saltLen:DWORD;  entropy:LPCVOID;  entropyLen:DWORD;  data:LPCVOID;  dataLen:DWORD;  hashAlg:ALG_ID;  outKey:LPVOID;  outKeyLen:DWORD):boolean;
var
	status:BOOL = FALSE;
	pKey:LPCVOID = nil;
	dgstMasterKey:array [0..SHA_DIGEST_LENGTH-1] of byte;
	tmp:PBYTE;
begin
log('**** dpapi_sessionkey ****');
	if masterkeyLen = SHA_DIGEST_LENGTH
                then pKey := masterkey
	else if crypto_hash(CALG_SHA1, masterkey, masterkeyLen, @dgstMasterKey[0], SHA_DIGEST_LENGTH)
                then pKey := @dgstMasterKey[0];

	if pKey<>nil then
	begin
		if (hashAlg = CALG_SHA1) and ((entropy<>nil) or (data<>nil)) then
                   status := dpapi_hmac_sha1_incorrect(masterkey, masterkeyLen, salt, saltLen, entropy, entropyLen, data, dataLen, outKey)
		else
                begin
                tmp := PBYTE(LocalAlloc(LPTR, saltLen + entropyLen + dataLen)) ;
                if tmp<>nil then
		begin
			//RtlCopyMemory(tmp, salt, saltLen);
                        CopyMemory(tmp, salt, saltLen);
			if ((entropy<>nil) and (entropyLen>0)) then
				//RtlCopyMemory(tmp + saltLen, entropy, entropyLen);
                                CopyMemory(tmp + saltLen, entropy, entropyLen);
			if ((data<>nil) and (dataLen>0)) then
				//RtlCopyMemory(tmp + saltLen + entropyLen, data, dataLen);
                                CopyMemory(tmp + saltLen + entropyLen, data, dataLen);
			status := crypto_hash_hmac(hashAlg, pKey, SHA_DIGEST_LENGTH, tmp, saltLen + entropyLen + dataLen, outKey, outKeyLen);
			LocalFree(thandle(tmp));
		end;

                end;
        end;
	result:= status;
        log('**** dpapi_sessionkey:'+booltostr(status)+' ****')
end;

function crypto_DeriveKeyRaw( hashId:ALG_ID;  hash:LPVOID;  hashLen:DWORD; key:LPVOID; keyLen:DWORD):boolean;
var
        status:BOOL = FALSE;
	buffer:array [0..151] of byte;
        ipad:array [0..63] of byte;
        opad:array [0..63] of byte;
	i:DWORD;
        //
        tmp:tbytes;
begin
log('**** crypto_DeriveKeyRaw ****');
log('hashId:'+inttostr(hashId));
log('hashLen:'+inttostr(hashLen));
//log('hash:'+ByteToHexaString (hash,hashLen));
log('keyLen:'+inttostr(keyLen));
//log('key:'+ByteToHexaString (key,keyLen));
	//if status = (hashLen >= keyLen) then
        if  (hashLen >= keyLen) then
		//RtlCopyMemory(key, hash, keyLen);
        begin
        CopyMemory(key, hash, keyLen);
        status:=true;
        end
        else
	begin
		//RtlFillMemory(ipad, sizeof(ipad), '6');
                FillByte(ipad,sizeof(ipad),ord('6'));
		//RtlFillMemory(opad, sizeof(opad), '\\');
                FillByte(opad,sizeof(opad),ord('\'));
		for i:= 0 to hashLen-1 do
		begin
			ipad[i] :=ipad[i] xor PBYTE(hash)[i];
			opad[i] :=opad[i] xor PBYTE(hash)[i];
		end;

                if crypto_hash(hashId, @ipad[0], sizeof(ipad), @buffer[0], hashLen) then
                        status := crypto_hash(hashId, @opad[0], sizeof(opad), @buffer[hashLen], hashLen);
                        //status := crypto_hash(hashId, @opad[0], sizeof(opad), pointer(@buffer[0])+hashlen, hashLen);
			if status then
				//RtlCopyMemory(key, buffer, min(keyLen, 2 * hashLen));
                                  CopyMemory(key, @buffer[0], min(keyLen, 2 * hashLen));
                        //

	end;
	result:= status;
        log('**** crypto_DeriveKeyRaw:'+booltostr(status)+' ****')
end;

function dpapi_unprotect_blob(blob:PDPAPI_BLOB;  masterkey:LPCVOID; masterkeyLen:DWORD; entropy:LPCVOID;  entropyLen:DWORD; password:LPCWSTR; var dataOut:LPVOID; var dataOutLen:DWORD):boolean;
var
	status:BOOL = FALSE; iStatus:bool=true;
	hmac:PVOID=nil;key:PVOID=nil;hashPassword:PVOID = nil;
	hSessionProv:HCRYPTPROV;
	hSessionKey:HCRYPTKEY;
	hashLen,cryptLen, hashPasswordLen:DWORD;
	passwordHash:ALG_ID;
        //
        tmp:tbytes;
begin
log('**** dpapi_unprotect_blob ****');
log('masterkey:'+ByteToHexaString (masterkey,masterkeyLen));
	//REM HEREHEREHERE

        //iStatus = !password;
        if password<>nil then istatus:=false;

        hashLen :=  blob.dwAlgHashLen div 8;
        cryptLen := blob.dwAlgCryptLen div 8;



	log('masterkeyLen:'+inttostr(masterkeyLen));
	log('entropyLen:'+inttostr(entropyLen ));
        log('hashLen:'+inttostr(hashLen ));
        log('cryptLen:'+inttostr(cryptLen ));

        log('algCrypt:'+inttostr(blob.algCrypt ));

        log('istatus:'+booltostr(istatus ));

	if (blob.algCrypt = CALG_3DES) and (cryptLen < (192 div 8)) then cryptLen := 192 div 8;

        {
	if(!iStatus)
	begin
		kprintf(L"!iStatus\n");
		if(blob->algHash == CALG_SHA_512)
		begin
			passwordHash = CALG_SHA_512;
			hashPasswordLen = hashLen;
		end
		else
		begin
			passwordHash = CALG_SHA1;
			hashPasswordLen = SHA_DIGEST_LENGTH;
		end
		if(hashPassword = LocalAlloc(LPTR, hashPasswordLen))
			iStatus = kull_m_crypto_hash(passwordHash, password, (DWORD) (wcslen(password) * sizeof(wchar_t)), hashPassword, hashPasswordLen);
	end
        }

	if (iStatus) then
	begin
		//kprintf(L"iStatus\n");
                hmac := pointer(LocalAlloc(LPTR, hashLen));
		if hmac<>nil then
		begin
                        if hashPassword =nil then hashPasswordLen:=0;
			if dpapi_sessionkey(masterkey, masterkeyLen, @blob.pbSalt[0], blob.dwSaltLen, entropy, entropyLen, hashPassword, hashPasswordLen , blob.algHash, hmac, hashLen) then
			begin
                        setlength(tmp,hashLen );
                        CopyMemory(@tmp[0],hmac,hashLen );
                        log('hmac:'+ByteToHexaString (tmp));
                                key := pointer(LocalAlloc(LPTR, cryptLen));
				if key<>nil then
				begin
					if crypto_DeriveKeyRaw(blob.algHash, hmac, hashLen, key, cryptLen) then
					begin
                                          setlength(tmp,cryptLen );
                                          CopyMemory(@tmp[0],key,cryptLen );
                                          log('key:'+ByteToHexaString (tmp));
						if crypto_hkey_session(blob.algCrypt, key, cryptLen, 0, hSessionKey, hSessionProv) then
						begin
                                                        dataOut := pointer(LocalAlloc(LPTR, blob.dwDataLen));
							if dataout<>nil then
							begin
								//RtlCopyMemory(*dataOut, blob->pbData, blob->dwDataLen);
                                                                CopyMemory(dataOut, @blob.pbData[0], blob.dwDataLen);
								dataOutLen := blob.dwDataLen;
                                                                setlength(tmp,blob.dwDataLen );
                                                                CopyMemory(@tmp[0],@blob.pbData[0],blob.dwDataLen );
                                                                log('blob.pbData:'+ByteToHexaString (tmp));
								status := CryptDecrypt(hSessionKey, 0, TRUE, 0, LPBYTE(dataOut), dataOutLen);
								if status=false then
								begin
									LocalFree(thandle(dataOut));
									log('CryptDecrypt not OK');
								end;
							end;
							CryptDestroyKey(hSessionKey);
							if not crypto_close_hprov_delete_container(hSessionProv) then ;
								//PRINT_ERROR_AUTO(L"kull_m_crypto_close_hprov_delete_container");
						end
						else ; //PRINT_ERROR_AUTO(L"kull_m_crypto_hkey_session");
					end;
					LocalFree(thandle(key));
				end;
			end;
			LocalFree(thandle(hmac));
		end;
	end;
	if hashPassword<>nil then
		LocalFree(thandle(hashPassword));
	result:= status;
        log('**** dpapi_unprotect_blob:'+BoolToStr (status)+' ****');
end;

{ BSwap sur entier 32 bits }
{$ASMMODE intel}
function BSwap0(const a : uint32) : uint32;
asm
  BSWAP EAX;
end;

function BSwap2(const a : uint32) : uint32;
var
         b:array[0..3] of byte;
begin
copymemory(@b[0],@a,4);
result:=(b[0]*(256*256*256))+(b[1]*(256*256))+(b[2]*(256))+b[3];
end;

function crypto_pkcs5_pbkdf2_hmac(calgid:DWORD;  password:LPCVOID;  passwordLen:DWORD;  salt:LPCVOID;  saltLen:DWORD;  iterations:DWORD; key:LPBYTE;  keyLen:DWORD;  isDpapiInternal:BOOL):boolean;
var
	 status:BOOL = FALSE;
	 hProv:HCRYPTPROV;
	 hHash:HCRYPTHASH;
	 sizeHmac, count, i, j, r:DWORD;
	 asalt, obuf, d1:PBYTE;
         //
         tmp:tbytes;
         u:uint32;
begin
log('**** crypto_pkcs5_pbkdf2_hmac ****',0);
setlength(tmp,passwordlen );
CopyMemory(@tmp[0],password,passwordlen );
log('password:'+ByteToHexaString(tmp),0);
setlength(tmp,saltlen );
CopyMemory(@tmp[0],salt,saltlen );
log('salt:'+ByteToHexaString(tmp),0);

	if CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
	begin
		if CryptCreateHash(hProv, calgid, 0, 0, hHash) then
		begin
			if CryptGetHashParam(hHash, HP_HASHVAL, nil, sizeHmac, 0) then
			begin
                        asalt := PBYTE (LocalAlloc(LPTR, saltLen + sizeof(DWORD)));
				if asalt<>nil then
				begin
                                obuf := PBYTE (LocalAlloc(LPTR, sizeHmac));
					if obuf<>nil then
					begin
                                        d1 := PBYTE(LocalAlloc(LPTR, sizeHmac));
						if d1<>nil then
						begin
							status := TRUE;
							//RtlCopyMemory(asalt, salt, saltLen);
                                                        CopyMemory(asalt, salt, saltLen);
							//for (count = 1; keyLen > 0; count++)
                                                        count:=1;
                                                        while keylen>0 do
                                                        begin
								//*(PDWORD) (asalt + saltLen) = _byteswap_ulong(count);
                                                                pdword(asalt + saltLen)^ := bswap2(count);
                                                                //log(inttohex(nativeuint(asalt),sizeof(nativeuint)),0);
                                                                //log(inttohex(nativeuint(asalt + saltLen),sizeof(nativeuint)),0);
                                                                log('count:'+inttostr((count)),0);
                                                                //log('bswap(count):'+inttostr(bswap2(count)),0);
                                                                //log('pdword(asalt + saltLen)^:'+inttostr(pdword(asalt + saltLen)^),0);
								crypto_hash_hmac(calgid, password, passwordLen, asalt, saltLen + 4, d1, sizeHmac);
                                                                //
                                                                setlength(tmp,sizeHmac );
                                                                CopyMemory(@tmp[0],d1,sizeHmac );
                                                                log('hmac:'+ByteToHexaString(tmp),0);
                                                                //
                                                                //RtlCopyMemory(obuf, d1, sizeHmac);
                                                                CopyMemory(obuf, d1, sizeHmac);
								for i:= 1 to iterations-1 do
								begin
                                                                log('iteration:'+inttostr(i),0);
									crypto_hash_hmac(calgid, password, passwordLen, d1, sizeHmac, d1, sizeHmac);
                                                                        j:=0;
                                                                        //for (j = 0; j < sizeHmac; j++)
                                                                        while j<sizeHmac do
                                                                        begin
                                                                                //obuf[j] ^= d1[j]; //Bitwise exclusive/inclusive OR assignment
										obuf[j] := obuf[j] xor d1[j];
                                                                                inc(j);
                                                                        end;
                                                                        if (isDpapiInternal) then // thank you MS!
										//RtlCopyMemory(d1, obuf, sizeHmac);
                                                                                CopyMemory(d1, obuf, sizeHmac);
								end;
								r := min(keyLen, sizeHmac);
								//RtlCopyMemory(key, obuf, r);
                                                                CopyMemory(key, obuf, r);
								key += r;
								keyLen -= r;
                                                                inc(count); //elc
							end;
							LocalFree(thandle(d1));
						end;
						LocalFree(thandle(obuf));
					end;
					LocalFree(thandle(asalt));
				end;
			end;
			CryptDestroyHash(hHash);
		end;
		CryptReleaseContext(hProv, 0);
	end;
	result:= status;
end;


function dpapi_unprotect_masterkey_with_shaDerivedkey(masterkey:tmasterkey;  shaDerivedkey:LPCVOID;shaDerivedkeyLen:DWORD; var output:PVOID;var outputLen:DWORD):boolean;
var
  	 status:BOOL = FALSE;
	 hSessionProv:HCRYPTPROV;
	 hSessionKey:HCRYPTKEY;
	 HMACAlg:ALG_ID;
	 HMACLen, BlockLen, KeyLen, OutLen:DWORD;
	 HMACHash, CryptBuffer, hmac1, hmac2:PVOID;
         //
         temp:tbytes;
begin
result:=false;

log('**** dpapi_unprotect_masterkey_with_shaDerivedkey ****',0);

if (shaDerivedkey=nil) or (shaDerivedkeyLen=0) then
   begin
   log('shaDerivedkey is null',0);
   exit;
   end;

	//HMACAlg = (masterkey->algHash == CALG_HMAC) ? CALG_SHA1 : masterkey->algHash;
        if masterkey.algHash =CALG_HMAC then HMACAlg:=CALG_SHA1 else HMACAlg:=masterkey.algHash ;
	HMACLen := crypto_hash_len(HMACAlg);
	KeyLen :=  crypto_cipher_keylen(masterkey.algCrypt);
	BlockLen := crypto_cipher_blocklen(masterkey.algCrypt);

        log('HMACAlg:'+inttohex(HMACAlg,sizeof(HMACAlg)),0);
        log('HMACLen:'+inttostr(HMACLen),0);
        log('KeyLen:'+inttostr(KeyLen),0);
        log('BlockLen:'+inttostr(BlockLen),0);


        HMACHash := pointer(LocalAlloc(LPTR, KeyLen + BlockLen));
        if HMACHash<>nil then
	begin
		if crypto_pkcs5_pbkdf2_hmac(HMACAlg, shaDerivedkey, shaDerivedkeyLen, @masterkey.salt[0], sizeof(masterkey.salt), masterkey.rounds, HMACHash, KeyLen + BlockLen, TRUE) then
                begin
                setlength(temp,KeyLen + BlockLen);
                CopyMemory(@temp[0],HMACHash ,keylen+BlockLen);
                log('HMACHash:'+ByteToHexaString (temp),0);
                log('crypto_pkcs5_pbkdf2_hmac ok',0);
			if crypto_hkey_session(masterkey.algCrypt, HMACHash, KeyLen, 0, hSessionKey, hSessionProv) then
                        begin
                        log('crypto_hkey_session ok',0);
				if CryptSetKeyParam(hSessionKey, KP_IV, HMACHash + KeyLen, 0) then
				begin
                                log('CryptSetKeyParam ok',0);
					OutLen := length(masterkey.pbkey);
                                        log('OutLen:'+inttostr(OutLen),0);
                                        CryptBuffer := pointer(LocalAlloc(LPTR, OutLen));
					if CryptBuffer<>nil then
					begin
						//RtlCopyMemory(CryptBuffer, masterkey->pbKey, OutLen);
                                                copymemory(CryptBuffer, @masterkey.pbKey[0], OutLen);
                                                setlength(temp,OutLen);
                                                CopyMemory(@temp[0],CryptBuffer ,OutLen);
                                                log('CryptBuffer:'+ByteToHexaString (temp),0);
						if CryptDecrypt(hSessionKey, 0, FALSE, 0,  CryptBuffer, OutLen) then
						begin
                                                log('CryptDecrypt ok',0);
							//*outputLen = OutLen - 16 - HMACLen - ((masterkey->algCrypt == CALG_3DES) ? 4 : 0); // reversed
                                                        if masterkey.algCrypt = CALG_3DES
                                                           then outputLen:=OutLen - 16 - HMACLen - 4
                                                           else outputLen:=OutLen - 16 - HMACLen - 0;
                                                        log('outputLen:'+inttostr(outputLen),0);
                                                        hmac1 := pointer(LocalAlloc(LPTR, HMACLen));
                                                        if hmac1<>nil then
							begin
								if crypto_hash_hmac(HMACAlg, shaDerivedkey, shaDerivedkeyLen, CryptBuffer, 16, hmac1, HMACLen) then
								begin
                                                                log('crypto_hash_hmac #1 ok',0);
                                                                setlength(temp,HMACLen);
                                                                CopyMemory(@temp[0],hmac1 ,HMACLen);
                                                                log('hmac1:'+ByteToHexaString (temp),0);
                                                                        hmac2 := pointer(LocalAlloc(LPTR, HMACLen));
									if hmac2<>nil then
									begin
										if crypto_hash_hmac(HMACAlg, hmac1, HMACLen, CryptBuffer + OutLen - outputLen, outputLen, hmac2, HMACLen) then
										begin
                                                                                log('crypto_hash_hmac #2 ok',0);
											//if(status = RtlEqualMemory(hmac2, (PBYTE) CryptBuffer + 16, HMACLen))
                                                                                        //setlength(temp,HMACLen);
                                                                                        //CopyMemory(@temp[0],hmac2 ,HMACLen);
                                                                                        //log('hmac2:'+ByteToHexaString (temp),0);
                                                                                        log('hmac2:'+ByteToHexaString (hmac2,HMACLen),0);
                                                                                        status:=CompareMem (hmac2, CryptBuffer + 16, HMACLen);
                                                                                        if  status then
                                                                                        begin
                                                                                        log('CompareMem=true',0);
                                                                                        output := pointer(LocalAlloc(LPTR, outputLen));
											if output<>nil then
											   //RtlCopyMemory(*output, (PBYTE) CryptBuffer + OutLen - *outputLen, *outputLen);
                                                                                           copymemory(output,CryptBuffer + OutLen - outputLen,outputLen);
                                                                                        setlength(temp,outputLen);
                                                                                        CopyMemory(@temp[0],output ,outputLen);
                                                                                        log('output:'+ByteToHexaString (temp),0);
                                                                                        end else log('CompareMem=false',0);;
										end;
										LocalFree(thandle(hmac2));
									end;
								end;
								LocalFree(thandle(hmac1));
							end;
						end;
						LocalFree(thandle(CryptBuffer));
					end;
				end;
				CryptDestroyKey(hSessionKey);
				if not crypto_close_hprov_delete_container(hSessionProv) then
					log('crypto_close_hprov_delete_container error');
			end
			else log('crypto_hkey_session error');
		end;
		LocalFree(thandle(HMACHash));
	end;
	result:= status;
end;

{
B. CREDHIST
1. pwdhash = MD4(password) or SHA1(password)
2. pwdhash_key = HMACSHA1(pwdhash, user_sid)
3. PBKDF2(…, pwdhash_key,…), another elements from the file. Windows 10 no domain: SHA512, AES-256, 8000 rounds.
4. Control – HMACSHA512
}
function dpapi_unprotect_credhist_entry_with_shaDerivedkey( entry:tDPAPI_CREDHIST_ENTRY; shaDerivedkey:LPCVOID; shaDerivedkeyLen: DWORD; md4hash:PVOID; sha1hash:PVOID):boolean;
var
	 status:BOOL = FALSE;
	 hSessionProv:HCRYPTPROV;
	 hSessionKey:HCRYPTKEY;
	 HMACAlg:ALG_ID;
	 HMACLen, BlockLen, KeyLen, OutLen:DWORD;
	 HMACHash, CryptBuffer:PVOID;
	 i:DWORD;
begin
log('**** dpapi_unprotect_credhist_entry_with_shaDerivedkey ****');
      	//HMACAlg := (entry->algHash == CALG_HMAC) ? CALG_SHA1 : entry->algHash;
        if entry.algHash =CALG_HMAC then HMACAlg:=CALG_SHA1 else HMACAlg:=entry.algHash;
	HMACLen := crypto_hash_len(HMACAlg);
	KeyLen :=  crypto_cipher_keylen(entry.algCrypt);
	BlockLen := crypto_cipher_blocklen(entry.algCrypt);

        log('HMACAlg:'+inttohex(HMACAlg,sizeof(HMACAlg)),0);
        log('HMACLen:'+inttostr(HMACLen),0);
        log('KeyLen:'+inttostr(KeyLen),0);
        log('BlockLen:'+inttostr(BlockLen),0);

        HMACHash := pvoid(LocalAlloc(LPTR, KeyLen + BlockLen));
	if HMACHash<>nil then
	begin
		if crypto_pkcs5_pbkdf2_hmac(HMACAlg, shaDerivedkey, shaDerivedkeyLen, @entry.salt[0], sizeof(entry.salt), entry.rounds, PBYTE(HMACHash), KeyLen + BlockLen, TRUE) then
		begin
                log('crypto_pkcs5_pbkdf2_hmac ok');
			if crypto_hkey_session(entry.algCrypt, HMACHash, KeyLen, 0, hSessionKey, hSessionProv) then
			begin
                        log('crypto_hkey_session ok');
				if CryptSetKeyParam(hSessionKey, KP_IV, PBYTE(HMACHash + KeyLen), 0) then
				begin
                                log('CryptSetKeyParam ok');
					OutLen := entry.__dwSecretLen;
                                        log('OutLen:'+inttostr(OutLen),0);
                                        CryptBuffer := pvoid(LocalAlloc(LPTR, OutLen));
					if CryptBuffer<>nil then
					begin
						//RtlCopyMemory(CryptBuffer, entry->pSecret, OutLen);
                                                CopyMemory(CryptBuffer, @entry.pSecret[0], OutLen);
						if CryptDecrypt(hSessionKey, 0, FALSE, 0, PBYTE(CryptBuffer), OutLen) then
						begin
                                                log('CryptDecrypt ok');
							//RtlCopyMemory(sha1hash, CryptBuffer, min(entry->sha1Len, SHA_DIGEST_LENGTH));
                                                        CopyMemory(sha1hash, CryptBuffer, min(entry.sha1Len, SHA_DIGEST_LENGTH));
							//RtlCopyMemory(md4hash, (PBYTE) CryptBuffer + entry->sha1Len, min(entry->md4Len, LM_NTLM_HASH_LENGTH));
                                                        CopyMemory(md4hash, CryptBuffer + entry.sha1Len, min(entry.md4Len, LM_NTLM_HASH_LENGTH));
                                                        //log('CryptBuffer:'+ByteToHexaString (CryptBuffer,min(entry.sha1Len, SHA_DIGEST_LENGTH)));
							status := TRUE;

                                                        {
                                                        //lets skip MD4 for now
							if bool(entry.md4Len - LM_NTLM_HASH_LENGTH) then
								for i:= 0 to (entry.md4Len - LM_NTLM_HASH_LENGTH)-1 do
                                                                begin
                                                                if status=false then break;
									status := status and not bool(PBYTE( CryptBuffer + entry.sha1Len + LM_NTLM_HASH_LENGTH + i));
                                                                end;
                                                        }
                                                end;
						LocalFree(thandle(CryptBuffer));
					end;
				end;
				CryptDestroyKey(hSessionKey);
				if crypto_close_hprov_delete_container(hSessionProv)=false then
					log('crypto_close_hprov_delete_container error');
			end
			else log('crypto_hkey_session error');
		end;
		LocalFree(thandle(HMACHash));
	end;
	result:= status;
end;

{
function InitAPI: Boolean;
begin
 Result := False;
 if Win32Platform <> VER_PLATFORM_WIN32_NT then Exit;
 if HApi = 0 then HApi := LoadLibrary(apilib);
 if HApi > HINSTANCE_ERROR then
 begin
   @CryptProtectMemory  := GetProcAddress(HApi, 'CryptProtectMemory');
   @CryptUnProtectMemory := GetProcAddress(HApi, 'CryptUnProtectMemory');
    Result := True;
 end;
end;

procedure FreeAPI;
begin
 if HApi <> 0 then FreeLibrary(HApi);
 HApi := 0;
end;
}

//initialization InitAPI;
//finalization FreeAPI;

end.
