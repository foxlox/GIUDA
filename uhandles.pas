unit uhandles;

{$mode objfpc}{$H+}

interface

uses windows,ntdll,sysutils,uadvapi32,jwawinuser,jwanative,jwantstatus;

type tobj=record
     h:thandle;
     s:array [0..255] of char;
     end;

type tcallback=function(param:pointer=nil):dword;stdcall;

{
function GetModuleFileNameExA(hProcess : THandle; hModule : THandle;
                             lpFileName : pchar;
                             nSize : DWORD): DWORD; stdcall; external 'psapi.dll';

function GetProcessImageFileNameA(
   hProcess:HANDLE;
    lpImageFileName:LPSTR;
    nSize:DWORD):dword; stdcall; external 'psapi.dll';
}

function QueryFullProcessImageNameA(
   hProcess:HANDLE;
    dwFlags:DWORD;
    lpExeName:LPSTR;
    lpdwSize:PDWORD):bool; stdcall; external 'kernel32.dll';



//var ptr:pointer;

implementation



var
  lpid:word=0;
  ltype:string='';




end.
