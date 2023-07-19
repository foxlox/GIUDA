{$mode delphi}
unit udebug;

interface

uses windows,sysutils;

const
  SYMOPT_ALLOW_ABSOLUTE_SYMBOLS = $00000800; // Enables the use of symbols that are stored with absolute addresses. Most symbols are stored as RVAs from the base of the module. DbgHelp translates them to absolute addresses. There are symbols that are stored as an absolute address. These have very specialized purposes and are typically not used.
        SYMOPT_ALLOW_ZERO_ADDRESS = $01000000; // Enables the use of symbols that do not have an address. By default; DbgHelp filters out symbols that do not have an address.
        SYMOPT_AUTO_PUBLICS = $00010000; // Do not search the public symbols when searching for symbols by address; or when enumerating symbols; unless they were not found in the global symbols or within the current scope. This option has no effect with SYMOPT_PUBLICS_ONLY.
        SYMOPT_CASE_INSENSITIVE = $00000001; // All symbol searches are insensitive to case.
        SYMOPT_DEBUG = $80000000; // Pass debug output through OutputDebugString or the SymRegisterCallbackProc64 callback function.
        SYMOPT_DEFERRED_LOADS = $00000004; // Symbols are not loaded until a reference is made requiring the symbols be loaded. This is the fastest; most efficient way to use the symbol handler.
        SYMOPT_DISABLE_SYMSRV_AUTODETECT = $02000000; // Disables the auto-detection of symbol server stores in the symbol path; even without the "SRV*" designation; maintaining compatibility with previous behavior. DbgHelp 6.6 and earlier:  This value is not supported.
        SYMOPT_EXACT_SYMBOLS = $00000400; // Do not load an unmatched .pdb file. Do not load export symbols if all else fails.
        SYMOPT_FAIL_CRITICAL_ERRORS = $00000200; // Do not display system dialog boxes when there is a media failure such as no media in a drive. Instead; the failure happens silently.
        SYMOPT_FAVOR_COMPRESSED = $00800000; // If there is both an uncompressed and a compressed file available; favor the compressed file. This option is good for slow connections.
        SYMOPT_FLAT_DIRECTORY = $00400000; // Symbols are stored in the root directory of the default downstream store. DbgHelp 6.1 and earlier:  This value is not supported.
        SYMOPT_IGNORE_CVREC = $00000080; // Ignore path information in the CodeView record of the image header when loading a .pdb file.
        SYMOPT_IGNORE_IMAGEDIR = $00200000; // Ignore the image directory. DbgHelp 6.1 and earlier:  This value is not supported.
        SYMOPT_IGNORE_NT_SYMPATH = $00001000; // Do not use the path specified by _NT_SYMBOL_PATH if the user calls SymSetSearchPath without a valid path. DbgHelp 5.1:  This value is not supported.
        SYMOPT_INCLUDE_32BIT_MODULES = $00002000; // When debugging on 64-bit Windows; include any 32-bit modules.
        SYMOPT_LOAD_ANYTHING = $00000040; // Disable checks to ensure a file (.exe; .dbg.; or .pdb) is the correct file. Instead; load the first file located.
        SYMOPT_LOAD_LINES = $00000010; // Loads line number information.
        SYMOPT_NO_CPP = $00000008; // All C++ decorated symbols containing the symbol separator "::" are replaced by "__". This option exists for debuggers that cannot handle parsing real C++ symbol names.
        SYMOPT_NO_IMAGE_SEARCH = $00020000; // Do not search the image for the symbol path when loading the symbols for a module if the module header cannot be read. DbgHelp 5.1:  This value is not supported.
        SYMOPT_NO_PROMPTS = $00080000; // Prevents prompting for validation from the symbol server.
        SYMOPT_NO_PUBLICS = $00008000; // Do not search the publics table for symbols. This option should have little effect because there are copies of the public symbols in the globals table. DbgHelp 5.1:  This value is not supported.
        SYMOPT_NO_UNQUALIFIED_LOADS = $00000100; // Prevents symbols from being loaded when the caller examines symbols across multiple modules. Examine only the module whose symbols have already been loaded.
        SYMOPT_OVERWRITE = $00100000; // Overwrite the downlevel store from the symbol store. DbgHelp 6.1 and earlier:  This value is not supported.
        SYMOPT_PUBLICS_ONLY = $00004000; // Do not use private symbols. The version of DbgHelp that shipped with earlier Windows release supported only public symbols; this option provides compatibility with this limitation. DbgHelp 5.1:  This value is not supported.
        SYMOPT_SECURE = $00040000; // DbgHelp will not load any symbol server other than SymSrv. SymSrv will not use the downstream store specified in _NT_SYMBOL_PATH. After this flag has been set; it cannot be cleared. DbgHelp 6.0 and 6.1:  This flag can be cleared. DbgHelp 5.1:  This value is not supported.
        SYMOPT_UNDNAME = $00000002; // All symbols are presented in undecorated form. This option has no effect on global or local symbols because they are stored undecorated. This option applies only to public symbols.

const
  //DbgHelpDll   = 'C:\windows\system32\dbghelp.dll';
  DbgHelpDll   = 'dbghelp.dll';
  SYMFLAG_FUNCTION = $00000800 or $200; // fonction ou export table

type
  _MODLOAD_DATA = record
    ssize: DWORD;                  // size of this struct
    ssig: DWORD;                   // signature identifying the passed data
    data: POINTER;                   // pointer to passed data
    size: DWORD;                   // size of passed data
    flags: DWORD;                  // options
  end;
  {$EXTERNALSYM _MODLOAD_DATA}
  MODLOAD_DATA = _MODLOAD_DATA;
  {$EXTERNALSYM MODLOAD_DATA}
  PMODLOAD_DATA = ^MODLOAD_DATA;
  {$EXTERNALSYM PMODLOAD_DATA}
  TModLoadData = MODLOAD_DATA;
  PModLoadData = PMODLOAD_DATA;

type
  TSYMBOL_INFO = record
    SizeOfStruct: DWORD; // 10 DWORD 5 uint64 256 AnsiChar => 336
    TypeIndex: DWORD;
    Reserved_1, Reserved_2: uint64;
    Index: DWORD;
    Size: DWORD;
    ModBase: int64;
    Flags: DWORD; // SYMFLAG_FUNCTION
    Value: Int64;
    Address: int64;
    Registre: DWORD;
    Scope: DWORD;
    Tag: DWORD;
    NameLen: DWORD;
    MaxNameLen: DWORD; //256
    Name: array[0..255] of Char;   // AnsiChar
  end;
  SYMBOL_INFO=TSYMBOL_INFO ;


 {
function SymLoadModuleEx(hProcess, hFile: THANDLE; ImageName, ModuleName: PAnsiChar; BaseOfDll: INT64;
  DllSize: DWORD; Data: PMODLOAD_DATA; Flag: DWORD): INT64; stdcall; external DbgHelpDll;

function SymInitialize(aHandle: HMODULE; aUserSearchPath: PChar;
  aInvadeProcess: Boolean): Boolean; stdcall; external DbgHelpDll;

function SymSetSearchPath(hProcess:HANDLE;SearchPath:pchar) : BOOL; stdcall;external DbgHelpDll;

function SymSetOptions(SymOptions: DWORD): DWORD; stdcall;external DbgHelpDll;

function SymFromName(hProcess: THANDLE; Name: pchar; Symbol: pointer): BOOL; stdcall;external DbgHelpDll;

function SymFromAddr(aHandle: HMODULE;
  aAdress: int64;
  aDisplacement: DWORD;
  aSymbolInfo: Pointer): Boolean; stdcall; external DbgHelpDll;

function SymCleanup(aHandle: HMODULE): Boolean; stdcall; external DbgHelpDll;
}

{
function ImageNtHeader(Base: Pointer): PIMAGE_NT_HEADERS; stdcall; external 'dbghelp.dll';
function ImageRvaToVa(NtHeaders: Pointer; Base: Pointer; Rva: ULONG;
  LastRvaSection: Pointer): Pointer; stdcall; external 'dbghelp.dll';
}

function _SymFromName(dllname,symbol:string;var address:nativeuint):boolean;
function _SymFromAddr(dllname:string;address:nativeuint;var name:string):boolean;

var
SymLoadModuleEx:function(hProcess, hFile: THANDLE; ImageName, ModuleName: PAnsiChar; BaseOfDll: INT64;DllSize: DWORD; Data: PMODLOAD_DATA; Flag: DWORD): INT64; stdcall;
SymInitialize:function (aHandle: HMODULE; aUserSearchPath: PChar; aInvadeProcess: Boolean): Boolean; stdcall;
SymSetOptions:function(SymOptions: DWORD): DWORD; stdcall;
SymFromName:function (hProcess: THANDLE; Name: pchar; Symbol: pointer): BOOL; stdcall;
SymFromAddr:function(aHandle: HMODULE;aAdress: int64;aDisplacement: DWORD;aSymbolInfo: Pointer): Boolean; stdcall;
SymCleanup:function(aHandle: HMODULE): Boolean; stdcall;

implementation

function _SymFromAddr(dllname:string;address:nativeuint;var name:string):boolean;
var
  Hprocess: HMODULE;
  i            : cardinal;
  Deplacement  : dword;
  SymbolInfo   : SYMBOL_INFO; //TSYMBOL_INFO;
  symbase:int64; //dword64
begin
result:=false;
hprocess:=getcurrentprocess;

//SymSetOptions(SYMOPT_UNDNAME or SYMOPT_DEBUG or SYMOPT_DEFERRED_LOADS or SYMOPT_PUBLICS_ONLY);
SymSetOptions(SYMOPT_UNDNAME or SYMOPT_DEBUG or SYMOPT_DEFERRED_LOADS or SYMOPT_CASE_INSENSITIVE );

//use _NT_SYMBOL_PROXY for proxy
//latest dbghelp versions uses IE proxy settings so no need to set the above

if GetEnvironmentVariable('_NT_SYMBOL_PATH')=''
   then SetEnvironmentVariable('_NT_SYMBOL_PATH', 'SRV*C:\\WINDOWS\\TEMP*http://msdl.microsoft.com/download/symbols');
//or we could use SymSetSearchPathW
//

if not SymInitialize(hProcess, nil, true) then
	begin
		raise exception.create('Error with SymInitialize : '+inttostr( GetLastError()));
		//CloseHandle(hProcess);
		exit;
	end;
//
SymBase:=0;
setlasterror(0);
SymBase:=udebug.SymLoadModuleEx(hProcess, 0, pchar(dllname), nil, 0 , 0, nil, 0);
if (SymBase=0) {or (GetLastError()<>ERROR_SUCCESS)} then
	begin
		raise exception.create('Error with SymLoadModuleEx : '+inttostr(GetLastError()));
		SymCleanup(hProcess);
		//CloseHandle(hProcess);
		exit;
	end;
//writeln('symbase:'+inttohex(symbase,sizeof(symbase)));
//
i := SizeOf(udebug.SYMBOL_INFO);
  zeromemory(@SymbolInfo, i);
  SymbolInfo.MaxNameLen := 256;
  SymbolInfo.SizeOfStruct :=  I - Length(SymbolInfo.Name) * SizeOf(SymbolInfo.Name[0]); // 88
  Deplacement := 0;
//
address:=symbase+address;
  if udebug.SymFromAddr(Hprocess, address, Deplacement, @SymbolInfo) then
    // mettre le handle du processus
  begin
    {
    if (SymbolInfo.Flags and SYMFLAG_FUNCTION) = 0 then
    begin
      raise exception.create('le symbole retourné n''est pas une fonction');
      Exit;
    end;
    }
    {SetLength(Result, SymbolInfo.NameLen);
    for i := 0 to SymbolInfo.NameLen do} name := SymbolInfo.Name;
    result:=true;
  end
  else begin
    i := GetLastError;
    raise exception.create('no data returned, ' + IntToStr(i));
  end;

  SymCleanup(Hprocess);

end;

function _SymFromName(dllname,symbol:string;var address:nativeuint):boolean;
var
hprocess:thandle;
symbase:int64; //dword64
//dllname:string;
i            : cardinal;
Deplacement  : dword;
SymbolInfo   : udebug.SYMBOL_INFO;
begin
result:=false;
hprocess:=getcurrentprocess;

//SymSetOptions(SYMOPT_UNDNAME or SYMOPT_DEBUG or SYMOPT_DEFERRED_LOADS or SYMOPT_PUBLICS_ONLY);
SymSetOptions(SYMOPT_UNDNAME or SYMOPT_DEBUG or SYMOPT_DEFERRED_LOADS or SYMOPT_CASE_INSENSITIVE );

//use _NT_SYMBOL_PROXY for proxy
//latest dbghelp versions uses IE proxy settings so no need to set the above

if GetEnvironmentVariable('_NT_SYMBOL_PATH')=''
   then SetEnvironmentVariable('_NT_SYMBOL_PATH', 'SRV*C:\\WINDOWS\\TEMP*http://msdl.microsoft.com/download/symbols');

//or we could use SymSetSearchPathW
//

if not SymInitialize(hProcess, nil, true) then
	begin
		raise exception.create('Error with SymInitialize : '+inttostr( GetLastError()));
		//CloseHandle(hProcess);
		exit;
	end;
//
//if not SymSetSearchPath(hprocess,'.;http://msdl.microsoft.com/download/symbols') then writeln('SymSetSearchPath failed');
//
SymBase:=0;
setlasterror(0);
SymBase:=udebug.SymLoadModuleEx(hProcess, 0, pchar(dllname), nil, 0 , 0, nil, 0);
if (SymBase=0)  {or (GetLastError()<>ERROR_SUCCESS)} then
	begin
      		SymCleanup(hProcess);
		raise exception.create('Error with SymLoadModuleEx : '+inttostr(GetLastError()));
		//CloseHandle(hProcess);
		exit;
	end;
//writeln('symbase:'+inttohex(symbase,sizeof(symbase)));
//
i := SizeOf(udebug.SYMBOL_INFO);
  zeromemory(@SymbolInfo, i);
  SymbolInfo.MaxNameLen := 256;
  SymbolInfo.SizeOfStruct :=  I - Length(SymbolInfo.Name) * SizeOf(SymbolInfo.Name[0]); // 88
  Deplacement := 0;
//
if not SymFromName(hProcess, pchar(symbol), @SymbolInfo) then
	begin
       		SymCleanup(hProcess);
		raise exception.create('Error with SymFromName : ' + inttostr(getLastError()));
		//CloseHandle(hProcess);
		//HeapFree(GetProcessHeap(), 0, Symbol);
		exit;
	end;

//writeln(inttohex(SymbolInfo.Address,sizeof(int64) ));
//writeln(inttohex(SymbolInfo.ModBase,sizeof(SymbolInfo.ModBase)));
//writeln(inttohex(symbase,sizeof(symbase)));
address :=  SymbolInfo.Address-symbase ;
result:=true;

SymCleanup(hProcess);

end;

function init_lib:boolean;
var
{$IFDEF win32}lib:cardinal;{$endif}
{$IFDEF win64}lib:int64;{$endif}
p:pchar;
begin
result:=false;
try
lib:=0;
lib:=loadlibrary(pchar(DbgHelpDll));
if lib<=0 then
  begin
  raise exception.Create  ('could not loadlibrary:'+inttostr(getlasterror));
  exit;
  end;
//
SymLoadModuleEx:=getProcAddress(lib,'SymLoadModuleEx');
SymInitialize:=getProcAddress(lib,'SymInitialize');
SymSetOptions:=getProcAddress(lib,'SymSetOptions');
SymFromName:=getProcAddress(lib,'SymFromName');
SymFromAddr:=getProcAddress(lib,'SymFromAddr');
SymCleanup:=getProcAddress(lib,'SymCleanup');
//
result:=true;
except
on e:exception do raise exception.Create ('loadlibrary error:'+e.message);
end;
end;


initialization
init_lib;

end.
 
