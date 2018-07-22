# r2frida_plugins

## interceptor.js
Interceptor gives the context, the stack trace, the result of the hooked function, the arguments psased to the function and allows you also to modify them.

Usage:
```bash
\interc <library_name> <function> <nmb_args_fn> <fmt> (<index_arg:new_values>)
```

Example:
```bash
\interc USER32.DLL MessageBoxW 4 %d,%S,%S,%d 2:0x12345678,3:0x30
```
In the example, MessageBoxW will be hooked and when it's called, the 4th argument (index begins at 0 and goes to nmb_args_fn-1) will be replaced by 0x30.

Output:
```
===============
1. StartServiceW called from:
0x51d9aa6
0x51d8f22
0x773d94e0 PivotMonet.exe!RtlUpdateTimer
0x77329ef7 PivotMonet.exe!RtlEqualUnicodeString
0x7732cd69 PivotMonet.exe!TpSetTimerEx
0x76308484 PivotMonet.exe!BaseThreadInitThunk
0x77342ec0 PivotMonet.exe!RtlValidSecurityDescriptor
0x77342e90 PivotMonet.exe!RtlValidSecurityDescriptor

2. Base Arguments:
0x3017c30
0
0

3. Context information:
Context  : {"pc":"0x51d9aa6","sp":"0x353f7dc","eax":"0x1","ecx":"0x2fa0000","edx":"0x2fa0000","ebx":"0x2fdd920","esp":"0x353f7dc","ebp":"0x353fa88","esi":"0x3017c30","edi":"0x3017c58","eip":"0x51d9aa6"}
Return   : 0x51d9aa6
ThreadId : 8100
Depth    : 0
Errornr  : undefined

4. Result for StartServiceW: 
0x0
===============
```

## resolver.js
Just a modified version of the basic resolver. It just takes the type as arguments.

Usage:
```
\resO {objc, module} <query>
```

Example:
```
\resO module exports:advapi32.dll!*
```

## stalky.js
Logs some specific instructions (useful for packed binaries for example).

Usage:
```
\stalky <tid> <instruction(s)> (<operands>)
```

Example:
```
\stalky * jmp eax,ebx,ecx,edx,esi,edi
```

## apilogger.js
Logs every call and find the symbols when possible.

Usage:
```
\apilog <tid/*>
```

## tracer.js
Traces and log everything in a file.

Usage:
```
\tracer <tid/*> <filepath>
```