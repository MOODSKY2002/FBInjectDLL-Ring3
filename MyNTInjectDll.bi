type _INJECT_BUFFER
    dim Code(511) as ubyte    
    union
        Path64    as UNICODE_STRING
        Path32    as UNICODE_STRING32
    end union        
    Buffer(487)   as wchar_t
    Module        as PVOID
    Complete      as ULONG
    Status        as NTSTATUS
end type
type INJECT_BUFFER  as _INJECT_BUFFER
type PINJECT_BUFFER as _INJECT_BUFFER ptr

Static Shared BBCode32(39) as ubyte = { _
   &H68, &H00, &H00, &H00, &H00, _              ' push ModuleHandle            offset +1 
   &H68, &H00, &H00, &H00, &H00, _              ' push ModuleFileName          offset +6
   &H6A, &H00, _                                ' push Flags  
   &H6A, &H00, _                                ' push PathToFile
   &HE8, &H00, &H00, &H00, &H00, _              ' call LdrLoadDll              offset +15
   &HBA, &H00, &H00, &H00, &H00, _              ' mov edx, COMPLETE_OFFSET     offset +20
   &HC7, &H02, &H7E, &H1E, &H37, &HC0, _        ' mov [edx], CALL_COMPLETE     
   &HBA, &H00, &H00, &H00, &H00, _              ' mov edx, STATUS_OFFSET       offset +31
   &H89, &H02, _                                ' mov [edx], eax
   &HC2, &H04, &H00 _                           ' ret 4
   }

Static Shared BBCode64(76) as ubyte = { _
   &H48, &H83, &HEC, &H28, _                                       'sub rsp, &H28
   &H48, &H31, &HC9, _                                             'xor rcx, rcx
   &H48, &H31, &HD2, _                                             'xor rdx, rdx
   &H49, &HB8, &H00, &H00, &H00, &H00, &H00, &H00, &H00, &H00, _   'mov r8, ModuleFileName   offset +12
   &H49, &HB9, &H00, &H00, &H00, &H00, &H00, &H00, &H00, &H00, _   'mov r9, ModuleHandle     offset +22
   &H48, &HB8, &H00, &H00, &H00, &H00, &H00, &H00, &H00, &H00, _   'mov rax, LdrLoadDll      offset +32
   &HFF, &HD0, _                                                   'call rax
   &H48, &HBA, &H00, &H00, &H00, &H00, &H00, &H00, &H00, &H00, _   'mov rdx, COMPLETE_OFFSET offset +44
   &HC7, &H02, &H7E, &H1E, &H37, &HC0, _                           'mov [rdx], CALL_COMPLETE 
   &H48, &HBA, &H00, &H00, &H00, &H00, &H00, &H00, &H00, &H00, _   'mov rdx, STATUS_OFFSET   offset +60
   &H89, &H02, _                                                   'mov [rdx], eax
   &H48, &H83, &HC4, &H28, _                                       'add rsp, &H28
   &HC3 _                                                          'ret
   }   
    
'取回远程进程函数地址(进程句柄,模块句柄,函数名称,进程位数32/64)
Declare function GetRemoteProcedureAddress(byval hProcess as HANDLE, byval hModule as HMODULE, byval funcName as string,BYVAL DllArch as DWORD) as PVOID
'取回远程进程模块地址(进程句柄,模块名称,进程位数32/64)
'注意只有x64进程可以获取x86模块,x86进程不能获取x64模块
Declare function GetRemoteModuleHandle(BYVAL ProcessHandle as HANDLE,BYVAL ModuleName as string,BYVAL DllArch as DWORD) as HMODULE


'基于BlackBone (BBGetWow64Code/BBGetNativeCode) 进行融合改造而成
function BBGetShellCode(byval Process as HANDLE,BYVAL rLdrLoadDll AS PVOID,byval DllPath as string,byval IsX64 as boolean) as PINJECT_BUFFER
   dim Status    as NTSTATUS
   dim pBuffer   as PINJECT_BUFFER
   dim size      as SIZE_T   = 4096
    
   status = NtAllocateVirtualMemory(Process, @pBuffer, 0, @size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if Status = STATUS_SUCCESS then       

         dim sString64 as UNICODE_STRING
         dim sString32 as UNICODE_STRING32
         dim sString   as PVOID
         dim wDllPath  as wstring * 512
         
         wDllPath = DllPath
         RtlInitUnicodeString @sString64,@wDllPath
         
         '拷贝UNICODE DLL路径         
         NtWriteVirtualMemory Process,@pBuffer->Buffer(0),sString64.Buffer,sString64.Length, null
         
         '拷贝ShellCode , 配置及拷贝UNICODE_STRING
         if IsX64 = True then        
            NtWriteVirtualMemory Process, pBuffer, @BBCode64(0),ubound(BBCode64) + 1, null
            sString64.Buffer        = @pBuffer->Buffer(0)
            NtWriteVirtualMemory Process,@pBuffer->Path64, @sString64, sizeof(sString64), null        
         else
            NtWriteVirtualMemory Process, pBuffer, @BBCode32(0),ubound(BBCode32) + 1, null
            sString32.Length        = sString64.Length
            sString32.MaximumLength = sString64.Length
            sString32.Buffer        = PtrToLong(@pBuffer->Buffer(0))
            NtWriteVirtualMemory Process,@pBuffer->Path32, @sString32, sizeof(sString32), null        
         end if

        'ShellCode关键信息填写
        if IsX64 = True then 
           dim sAdd64 as ULongInt 
           sAdd64 = PtrToPtr64(@pBuffer->Path64)
           NtWriteVirtualMemory Process,@pBuffer->Code(12), @sAdd64, sizeof(ULongInt), null
           sAdd64 = PtrToPtr64(@pBuffer->Module)
           NtWriteVirtualMemory Process,@pBuffer->Code(22), @sAdd64, sizeof(ULongInt), null
           sAdd64 = PtrToPtr64(rLdrLoadDll)
           NtWriteVirtualMemory Process,@pBuffer->Code(32), @sAdd64, sizeof(ULongInt), null
           sAdd64 = PtrToPtr64(@pBuffer->complete)
           NtWriteVirtualMemory Process,@pBuffer->Code(44), @sAdd64, sizeof(ULongInt), null
           sAdd64 = PtrToPtr64(@pBuffer->status)
           NtWriteVirtualMemory Process,@pBuffer->Code(60), @sAdd64, sizeof(ULongInt), null
        else
           dim sAdd32 as ULong
           sAdd32 = PtrToLong(@pBuffer->Module)
           NtWriteVirtualMemory Process,@pBuffer->Code(1), @sAdd32, sizeof(ULong), null
           sAdd32 = PtrToLong(@pBuffer->Path32)
           NtWriteVirtualMemory Process,@pBuffer->Code(6), @sAdd32, sizeof(ULong), null
           sAdd32 = PtrToLong(rLdrLoadDll) - (PtrToLong(pBuffer) + 15) - 5 + 1
           NtWriteVirtualMemory Process,@pBuffer->Code(15), @sAdd32, sizeof(ULong), null
           sAdd32 = PtrToLong(@pBuffer->complete)
           NtWriteVirtualMemory Process,@pBuffer->Code(20), @sAdd32, sizeof(ULong), null
           sAdd32 = PtrToLong(@pBuffer->status)
           NtWriteVirtualMemory Process,@pBuffer->Code(31), @sAdd32, sizeof(ULong), null 
        end if
        return pBuffer
    end if
    return NULL
end function

FUNCTION InjectRemoteDLL(byval sPID as long,byval sDllPath as string) as long
   Dim Cid              As CLIENT_ID
   Dim Oa               As OBJECT_ATTRIBUTES
   dim NTMod            as HMODULE
   dim rLdrLoadDll      as PVOID
   Dim wDllPath         As wString * 512
   dim ThisBit          AS WINBOOL
   dim mSize            as SIZE_T
   dim pUserBuf         as PINJECT_BUFFER
   DIM AS HANDLE hProcess,hThread
   DIM AS LONG Ret,PBit
   
   Function          = 1
   mSize             = 4096
   wDllPath          = sDllPath   
   Oa.Length         = SizeOf(Oa)        
   Cid.UniqueProcess = LongToHandle(sPID)   
   
   '打开进程
   Ret = NtOpenProcess (@hProcess,PROCESS_QUERY_INFORMATION + PROCESS_CREATE_THREAD + PROCESS_VM_OPERATION + PROCESS_VM_READ + PROCESS_VM_WRITE,@Oa,@Cid)
   If hProcess = 0 Then 
      function = 111000 + GetLastError
      Exit Function
   end if
   
   '判断进程位数
   IsWow64Process hProcess,@ThisBit
   if ThisBit = FALSE then PBit = 64 else PBit = 32                                 

   NTMod        = GetRemoteModuleHandle(hProcess, "NTDLL.dll",PBit)              '获取进程NTDLL模块地址
   rLdrLoadDll  = GetRemoteProcedureAddress(hProcess,NTMod,"LdrLoadDll",PBit)    '获取LdrLoadDll地址
   if NTMod = null or rLdrLoadDll = null then   
      function = 222000 + GetLastError
      goto sError
   end if
                            
   if PBit = 64 then 
      pUserBuf = BBGetShellCode(hProcess,rLdrLoadDll,sDllPath,true)
   else
      pUserBuf = BBGetShellCode(hProcess,rLdrLoadDll,sDllPath,FALSE)
   end if

   '创建远程线程
   if pUserBuf <> null then 
      Ret = NtCreateThreadEx(@hThread,&H1FFFFF,NULL,hProcess,pUserBuf,null,FALSE,NULL,NULL,NULL,NULL)
      If (hThread = 0) Then 
          function = 333000 + GetLastError
          goto sError
      end if

      WaitForSingleObject hThread, INFINITE
      NtFreeVirtualMemory hProcess,@pUserBuf,@mSize,MEM_RELEASE      
      NTClose hThread
   else
      function = 444000 + GetLastError      
   end if
      
sError:
   NTClose hProcess
end function

'取回远程进程模块地址(进程句柄,模块名称,进程位数32/64)
'注意只有x64进程可以获取x86模块,x86进程不能获取x64模块
function GetRemoteModuleHandle(BYVAL ProcessHandle as HANDLE,BYVAL ModuleName as string,BYVAL DllArch as DWORD) as HMODULE
   DIM ii AS LONG
   DIM hModules AS HMODULE PTR
   dim FullDllName as wstring * MAX_PATH
   DIM as DWORD cbNeeded,Result,Flags
   dim as string DllPath,sModuleName
   
   if instr(ModuleName,"\") = 0 then sModuleName = "\" & lcase(ModuleName) else sModuleName = lcase(ModuleName)
   select case DllArch
      case 32
         Flags = LIST_MODULES_32BIT
      case 64
         Flags = LIST_MODULES_64BIT
      case else
         Flags = LIST_MODULES_ALL
   end select
   
   if EnumProcessModulesEx(ProcessHandle, NULL, NULL, @cbNeeded, Flags) = 0 then exit function
   hModules = LocalAlloc(LPTR, cbNeeded)
   
   IF hModules THEN 
      if EnumProcessModulesEx(ProcessHandle, hModules, cbNeeded, @cbNeeded, Flags) THEN
         for ii = 0 to cbNeeded / sizeof(HMODULE)
            if GetModuleFileNameExW(ProcessHandle, hModules[ii], FullDllName, sizeof(FullDllName)) < 1 then exit for
            
            '找到目标模块则取回地址
            DllPath = lcase(FullDllName)
            if instr(DllPath,sModuleName) then 
               function = hModules[ii]
               exit for
            end if
         next
      end if
      LocalFree hModules
   end if
end function


'取回远程进程函数地址(进程句柄,模块句柄,函数名称,进程位数32/64)
function GetRemoteProcedureAddress(byval hProcess as HANDLE, byval hModule as HMODULE, byval funcName as string,BYVAL DllArch as DWORD) as PVOID
		dim DosHeader        as IMAGE_DOS_HEADER 
      dim Ret        as WINBOOL
      dim sModule    as UInteger  
      dim ii         as long
      dim ufuncName  as string
      
      ufuncName = ucase(funcName)
      sModule = HandleToHandle64(hModule)
      
      'DOS头 
		Ret = ReadProcessMemory(hProcess, sModule, @DosHeader, sizeof(DosHeader), NULL)
      if Ret = 0 then return 0
      
      'NT头
		dim NtHeaders64   as IMAGE_NT_HEADERS64
      dim NtHeaders32   as IMAGE_NT_HEADERS32
      dim DataDirectory as IMAGE_DATA_DIRECTORY
      select case DllArch
         case 64
            Ret = ReadProcessMemory(hProcess, (sModule + DosHeader.e_lfanew),@NtHeaders64, sizeof(NtHeaders64), NULL)
            if Ret = 0 then return 0
            DataDirectory = NtHeaders64.OptionalHeader.DataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
         case 32
            Ret = ReadProcessMemory(hProcess, (sModule + DosHeader.e_lfanew),@NtHeaders32, sizeof(NtHeaders32), NULL)
            if Ret = 0 then return 0
            DataDirectory = NtHeaders32.OptionalHeader.DataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
      end select
      if DataDirectory.VirtualAddress = 0 then return 0

      'EXPORT导出表
		dim ExportDirectory as IMAGE_EXPORT_DIRECTORY
		Ret = ReadProcessMemory(hProcess, (sModule + DataDirectory.VirtualAddress), @ExportDirectory, sizeof(ExportDirectory), NULL)
      if Ret = 0 then return 0

      '函数地址表
      dim nameTable(ExportDirectory.NumberOfNames) as DWORD
      Ret = ReadProcessMemory(hProcess, (sModule + ExportDirectory.AddressOfNames), @nameTable(0), sizeof(DWORD) * ExportDirectory.NumberOfNames, NULL)      
      if Ret = 0 then return 0
      
      dim zFunName as zstring * _MAX_FNAME
      dim Ordinal as WORD 
      dim NameRVA as DWORD
      for ii = 0 to ExportDirectory.NumberOfNames - 1
         Ret = ReadProcessMemory(hProcess, (sModule + nameTable(ii)), @zFunName, sizeof(zFunName), NULL) '依次取回函数表中的函数名称
         
         '函数名称匹配,返回其地址
         if ufuncName = ucase(zFunName) then 
            Ret = ReadProcessMemory(hProcess, (sModule + ExportDirectory.AddressOfNameOrdinals + ii * sizeof(WORD)), @Ordinal, sizeof(WORD), NULL)
            if Ret = 0 then return 0
            
            Ret = ReadProcessMemory(hProcess, (sModule + ExportDirectory.AddressOfFunctions + Ordinal * sizeof(DWORD)), @NameRVA, sizeof(DWORD), NULL)
            if Ret = 0 then return 0
            
            return sModule + NameRVA
         end if
      next
end function   