# InitMDIApp has a bunch of incorrect references to the DS that should be CS.

Here is the asm. Notice `MOV        word ptr [BP + wc.lpfnWndProc],0x6d6`, this is FrameWndProc (1020:06d6).
No doubt all the wndprocs are in here. 
```asm
                             //
                             // Code5
                             // ram:1020:0000-ram:1020:983f
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                               short __cdecl16far InitMDIApp(void)
                               assume CS = 0x1020
                               assume DS = 0x1120
             short             AX:2           <RETURN>
             WNDCLASS          Stack[-0x1e]   wc                                      XREF[22,83]: 1020:0009(*), 
                                                                                                   1020:005c(*), 
                                                                                                   1020:0076(*), 
                                                                                                   1020:00ab(*), 
                                                                                                   1020:00c5(*), 
                                                                                                   1020:00eb(*), 
                                                                                                   1020:0105(*), 
                                                                                                   1020:012b(*), 
                                                                                                   1020:0145(*), 
                                                                                                   1020:016b(*), 
                                                                                                   1020:0185(*), 
                                                                                                   1020:01b0(*), 
                                                                                                   1020:01ca(*), 
                                                                                                   1020:01f5(*), 
                                                                                                   1020:020f(*), 
                                                                                                   1020:023a(*), 
                                                                                                   1020:0254(*), 
                                                                                                   1020:027f(*), 
                                                                                                   1020:0299(*), 
                                                                                                   1020:02f2(*)  
                             Segment:    5
                             Offset:     00013700
                             Length:     983f
                             Min Alloc:  9840
                             Flags:      1d50
                                 Code
                                 Discardable
                                 Moveable
                                 Preload
                                 Impure (Non-shareable)
                             MDI::InitMDIApp                                 XREF[1]:     WinMain:1018:0051(c)  
       1020:0000 55              PUSH       BP
       1020:0001 8b ec           MOV        BP,SP
       1020:0003 81 ec 1c 00     SUB        SP,0x1c
       1020:0007 56              PUSH       SI
       1020:0008 57              PUSH       DI
       1020:0009 c7 46 e4        MOV        word ptr [BP + wc],0xb
                 0b 00
       1020:000e c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x6d6
                 d6 06
       1020:0013 c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1020
                 20 10
       1020:0018 c7 46 ea        MOV        word ptr [BP + wc.cbClsExtra],0x0
                 00 00
       1020:001d c7 46 ec        MOV        word ptr [BP + wc.cbWndExtra],0x0
                 00 00
       1020:0022 a1 10 53        MOV        AX,[c_common::hInst]
       1020:0025 89 46 ee        MOV        word ptr [BP + wc.hInstance],AX
       1020:0028 c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:002d b8 00 00        MOV        AX,0x0
       1020:0030 50              PUSH       AX
       1020:0031 b8 00 7f        MOV        AX,0x7f00
       1020:0034 ba 00 00        MOV        DX,0x0
       1020:0037 52              PUSH       DX
       1020:0038 50              PUSH       AX
       1020:0039 9a a0 02        CALLF      USER::LoadCursor                                 HCURSOR LoadCursor(HINSTANCE par
                 f8 14
       1020:003e 89 46 f2        MOV        word ptr [BP + wc.hCursor],AX
       1020:0041 c7 46 f4        MOV        word ptr [BP + wc.hbrBackground],0xd
                 0d 00
       1020:0046 b8 64 03        MOV        AX,0x364
       1020:0049 8c da           MOV        DX,DS
       1020:004b 89 46 f6        MOV        word ptr [BP + wc.lpszMenuName],AX
       1020:004e 89 56 f8        MOV        word ptr [BP + wc+0x14],DX
       1020:0051 b8 d6 01        MOV        AX,0x1d6
       1020:0054 8c da           MOV        DX,DS
       1020:0056 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:0059 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:005c 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:005f 8c d2           MOV        DX,SS
       1020:0061 52              PUSH       DX
       1020:0062 50              PUSH       AX
       1020:0063 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:0068 3d 00 00        CMP        AX,0x0
       1020:006b 74 03           JZ         LAB_1020_0070
       1020:006d e9 06 00        JMP        LAB_1020_0076
                             LAB_1020_0070                                   XREF[1]:     1020:006b(j)  
       1020:0070 b8 00 00        MOV        AX,0x0
       1020:0073 e9 0f 03        JMP        LAB_1020_0385
                             LAB_1020_0076                                   XREF[1]:     1020:006d(j)  
       1020:0076 c7 46 e4        MOV        word ptr [BP + wc],0x20b
                 0b 02
       1020:007b c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x5c92
                 92 5c
       1020:0080 c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1030
                 30 10
       1020:0085 c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:008a c7 46 f6        MOV        word ptr [BP + wc.lpszMenuName],0x0
                 00 00
       1020:008f c7 46 f8        MOV        word ptr [BP + wc+0x14],0x0
                 00 00
       1020:0094 b8 01 00        MOV        AX,0x1
       1020:0097 50              PUSH       AX
       1020:0098 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:009d 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:00a0 b8 02 02        MOV        AX,0x202
       1020:00a3 8c da           MOV        DX,DS
       1020:00a5 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:00a8 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:00ab 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:00ae 8c d2           MOV        DX,SS
       1020:00b0 52              PUSH       DX
       1020:00b1 50              PUSH       AX
       1020:00b2 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:00b7 3d 00 00        CMP        AX,0x0
       1020:00ba 74 03           JZ         LAB_1020_00bf
       1020:00bc e9 06 00        JMP        LAB_1020_00c5
                             LAB_1020_00bf                                   XREF[1]:     1020:00ba(j)  
       1020:00bf b8 00 00        MOV        AX,0x0
       1020:00c2 e9 c0 02        JMP        LAB_1020_0385
                             LAB_1020_00c5                                   XREF[1]:     1020:00bc(j)  
       1020:00c5 c7 46 e4        MOV        word ptr [BP + wc],0x20b
                 0b 02
       1020:00ca c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x32
                 32 00
       1020:00cf c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1058
                 58 10
       1020:00d4 b8 04 00        MOV        AX,0x4
       1020:00d7 50              PUSH       AX
       1020:00d8 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:00dd 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:00e0 b8 e2 01        MOV        AX,0x1e2
       1020:00e3 8c da           MOV        DX,DS
       1020:00e5 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:00e8 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:00eb 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:00ee 8c d2           MOV        DX,SS
       1020:00f0 52              PUSH       DX
       1020:00f1 50              PUSH       AX
       1020:00f2 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:00f7 3d 00 00        CMP        AX,0x0
       1020:00fa 74 03           JZ         LAB_1020_00ff
       1020:00fc e9 06 00        JMP        LAB_1020_0105
                             LAB_1020_00ff                                   XREF[1]:     1020:00fa(j)  
       1020:00ff b8 00 00        MOV        AX,0x0
       1020:0102 e9 80 02        JMP        LAB_1020_0385
                             LAB_1020_0105                                   XREF[1]:     1020:00fc(j)  
       1020:0105 c7 46 e4        MOV        word ptr [BP + wc],0x20b
                 0b 02
       1020:010a c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x0
                 00 00
       1020:010f c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1028
                 28 10
       1020:0114 b8 01 00        MOV        AX,0x1
       1020:0117 50              PUSH       AX
       1020:0118 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:011d 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:0120 b8 ec 01        MOV        AX,0x1ec
       1020:0123 8c da           MOV        DX,DS
       1020:0125 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:0128 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:012b 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:012e 8c d2           MOV        DX,SS
       1020:0130 52              PUSH       DX
       1020:0131 50              PUSH       AX
       1020:0132 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:0137 3d 00 00        CMP        AX,0x0
       1020:013a 74 03           JZ         LAB_1020_013f
       1020:013c e9 06 00        JMP        LAB_1020_0145
                             LAB_1020_013f                                   XREF[1]:     1020:013a(j)  
       1020:013f b8 00 00        MOV        AX,0x0
       1020:0142 e9 40 02        JMP        LAB_1020_0385
                             LAB_1020_0145                                   XREF[1]:     1020:013c(j)  
       1020:0145 c7 46 e4        MOV        word ptr [BP + wc],0x208
                 08 02
       1020:014a c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x1e
                 1e 00
       1020:014f c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1068
                 68 10
       1020:0154 b8 01 00        MOV        AX,0x1
       1020:0157 50              PUSH       AX
       1020:0158 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:015d 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:0160 b8 42 02        MOV        AX,0x242
       1020:0163 8c da           MOV        DX,DS
       1020:0165 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:0168 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:016b 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:016e 8c d2           MOV        DX,SS
       1020:0170 52              PUSH       DX
       1020:0171 50              PUSH       AX
       1020:0172 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:0177 3d 00 00        CMP        AX,0x0
       1020:017a 74 03           JZ         LAB_1020_017f
       1020:017c e9 06 00        JMP        LAB_1020_0185
                             LAB_1020_017f                                   XREF[1]:     1020:017a(j)  
       1020:017f b8 00 00        MOV        AX,0x0
       1020:0182 e9 00 02        JMP        LAB_1020_0385
                             LAB_1020_0185                                   XREF[1]:     1020:017c(j)  
       1020:0185 c7 46 e4        MOV        word ptr [BP + wc],0x200
                 00 02
       1020:018a c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x0
                 00 00
       1020:018f c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1048
                 48 10
       1020:0194 b8 01 00        MOV        AX,0x1
       1020:0197 50              PUSH       AX
       1020:0198 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:019d 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:01a0 c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:01a5 b8 f6 01        MOV        AX,0x1f6
       1020:01a8 8c da           MOV        DX,DS
       1020:01aa 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:01ad 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:01b0 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:01b3 8c d2           MOV        DX,SS
       1020:01b5 52              PUSH       DX
       1020:01b6 50              PUSH       AX
       1020:01b7 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:01bc 3d 00 00        CMP        AX,0x0
       1020:01bf 74 03           JZ         LAB_1020_01c4
       1020:01c1 e9 06 00        JMP        LAB_1020_01ca
                             LAB_1020_01c4                                   XREF[1]:     1020:01bf(j)  
       1020:01c4 b8 00 00        MOV        AX,0x0
       1020:01c7 e9 bb 01        JMP        LAB_1020_0385
                             LAB_1020_01ca                                   XREF[1]:     1020:01c1(j)  
       1020:01ca c7 46 e4        MOV        word ptr [BP + wc],0xa00
                 00 0a
       1020:01cf c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x0
                 00 00
       1020:01d4 c7 46 e8        MOV        word ptr [BP + wc+0x4],0x10c0
                 c0 10
       1020:01d9 b8 00 00        MOV        AX,0x0
       1020:01dc 50              PUSH       AX
       1020:01dd 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:01e2 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:01e5 c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:01ea b8 10 02        MOV        AX,0x210
       1020:01ed 8c da           MOV        DX,DS
       1020:01ef 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:01f2 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:01f5 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:01f8 8c d2           MOV        DX,SS
       1020:01fa 52              PUSH       DX
       1020:01fb 50              PUSH       AX
       1020:01fc 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:0201 3d 00 00        CMP        AX,0x0
       1020:0204 74 03           JZ         LAB_1020_0209
       1020:0206 e9 06 00        JMP        LAB_1020_020f
                             LAB_1020_0209                                   XREF[1]:     1020:0204(j)  
       1020:0209 b8 00 00        MOV        AX,0x0
       1020:020c e9 76 01        JMP        LAB_1020_0385
                             LAB_1020_020f                                   XREF[1]:     1020:0206(j)  
       1020:020f c7 46 e4        MOV        word ptr [BP + wc],0xa00
                 00 0a
       1020:0214 c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x19e4
                 e4 19
       1020:0219 c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1068
                 68 10
       1020:021e b8 00 00        MOV        AX,0x0
       1020:0221 50              PUSH       AX
       1020:0222 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:0227 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:022a c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:022f b8 4a 02        MOV        AX,0x24a
       1020:0232 8c da           MOV        DX,DS
       1020:0234 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:0237 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:023a 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:023d 8c d2           MOV        DX,SS
       1020:023f 52              PUSH       DX
       1020:0240 50              PUSH       AX
       1020:0241 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:0246 3d 00 00        CMP        AX,0x0
       1020:0249 74 03           JZ         LAB_1020_024e
       1020:024b e9 06 00        JMP        LAB_1020_0254
                             LAB_1020_024e                                   XREF[1]:     1020:0249(j)  
       1020:024e b8 00 00        MOV        AX,0x0
       1020:0251 e9 31 01        JMP        LAB_1020_0385
                             LAB_1020_0254                                   XREF[1]:     1020:024b(j)  
       1020:0254 c7 46 e4        MOV        word ptr [BP + wc],0x200
                 00 02
       1020:0259 c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x2876
                 76 28
       1020:025e c7 46 e8        MOV        word ptr [BP + wc+0x4],0x10d8
                 d8 10
       1020:0263 b8 01 00        MOV        AX,0x1
       1020:0266 50              PUSH       AX
       1020:0267 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:026c 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:026f c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:0274 b8 1c 02        MOV        AX,0x21c
       1020:0277 8c da           MOV        DX,DS
       1020:0279 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:027c 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:027f 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:0282 8c d2           MOV        DX,SS
       1020:0284 52              PUSH       DX
       1020:0285 50              PUSH       AX
       1020:0286 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:028b 3d 00 00        CMP        AX,0x0
       1020:028e 74 03           JZ         LAB_1020_0293
       1020:0290 e9 06 00        JMP        LAB_1020_0299
                             LAB_1020_0293                                   XREF[1]:     1020:028e(j)  
       1020:0293 b8 00 00        MOV        AX,0x0
       1020:0296 e9 ec 00        JMP        LAB_1020_0385
                             LAB_1020_0299                                   XREF[1]:     1020:0290(j)  
       1020:0299 c7 46 e4        MOV        word ptr [BP + wc],0x0
                 00 00
       1020:029e c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x9126
                 26 91
       1020:02a3 c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1020
                 20 10
       1020:02a8 c7 46 ea        MOV        word ptr [BP + wc.cbClsExtra],0x0
                 00 00
       1020:02ad c7 46 ec        MOV        word ptr [BP + wc.cbWndExtra],0x0
                 00 00
       1020:02b2 a1 10 53        MOV        AX,[c_common::hInst]
       1020:02b5 89 46 ee        MOV        word ptr [BP + wc.hInstance],AX
       1020:02b8 c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:02bd b8 00 00        MOV        AX,0x0
       1020:02c0 50              PUSH       AX
       1020:02c1 b8 00 7f        MOV        AX,0x7f00
       1020:02c4 ba 00 00        MOV        DX,0x0
       1020:02c7 52              PUSH       DX
       1020:02c8 50              PUSH       AX
       1020:02c9 9a a0 02        CALLF      USER::LoadCursor                                 HCURSOR LoadCursor(HINSTANCE par
                 f8 14
       1020:02ce 89 46 f2        MOV        word ptr [BP + wc.hCursor],AX
       1020:02d1 b8 04 00        MOV        AX,0x4
       1020:02d4 50              PUSH       AX
       1020:02d5 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:02da 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:02dd c7 46 f6        MOV        word ptr [BP + wc.lpszMenuName],0x0
                 00 00
       1020:02e2 c7 46 f8        MOV        word ptr [BP + wc+0x14],0x0
                 00 00
       1020:02e7 b8 2a 02        MOV        AX,0x22a
       1020:02ea 8c da           MOV        DX,DS
       1020:02ec 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:02ef 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:02f2 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:02f5 8c d2           MOV        DX,SS
       1020:02f7 52              PUSH       DX
       1020:02f8 50              PUSH       AX
       1020:02f9 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:02fe 3d 00 00        CMP        AX,0x0
       1020:0301 74 03           JZ         LAB_1020_0306
       1020:0303 e9 06 00        JMP        LAB_1020_030c
                             LAB_1020_0306                                   XREF[1]:     1020:0301(j)  
       1020:0306 b8 00 00        MOV        AX,0x0
       1020:0309 e9 79 00        JMP        LAB_1020_0385
                             LAB_1020_030c                                   XREF[1]:     1020:0303(j)  
       1020:030c c7 46 e4        MOV        word ptr [BP + wc],0xb
                 0b 00
       1020:0311 c7 46 e6        MOV        word ptr [BP + wc.lpfnWndProc],0x18
                 18 00
       1020:0316 c7 46 e8        MOV        word ptr [BP + wc+0x4],0x1108
                 08 11
       1020:031b c7 46 ea        MOV        word ptr [BP + wc.cbClsExtra],0x0
                 00 00
       1020:0320 c7 46 ec        MOV        word ptr [BP + wc.cbWndExtra],0x0
                 00 00
       1020:0325 a1 10 53        MOV        AX,[c_common::hInst]
       1020:0328 89 46 ee        MOV        word ptr [BP + wc.hInstance],AX
       1020:032b c7 46 f0        MOV        word ptr [BP + wc.hIcon],0x0
                 00 00
       1020:0330 b8 00 00        MOV        AX,0x0
       1020:0333 50              PUSH       AX
       1020:0334 b8 00 7f        MOV        AX,0x7f00
       1020:0337 ba 00 00        MOV        DX,0x0
       1020:033a 52              PUSH       DX
       1020:033b 50              PUSH       AX
       1020:033c 9a a0 02        CALLF      USER::LoadCursor                                 HCURSOR LoadCursor(HINSTANCE par
                 f8 14
       1020:0341 89 46 f2        MOV        word ptr [BP + wc.hCursor],AX
       1020:0344 b8 01 00        MOV        AX,0x1
       1020:0347 50              PUSH       AX
       1020:0348 9a 30 01        CALLF      GDI::GetStockObject                              HGDIOBJ GetStockObject(short par
                 f8 14
       1020:034d 89 46 f4        MOV        word ptr [BP + wc.hbrBackground],AX
       1020:0350 c7 46 f6        MOV        word ptr [BP + wc.lpszMenuName],0x0
                 00 00
       1020:0355 c7 46 f8        MOV        word ptr [BP + wc+0x14],0x0
                 00 00
       1020:035a b8 36 02        MOV        AX,0x236
       1020:035d 8c da           MOV        DX,DS
       1020:035f 89 46 fa        MOV        word ptr [BP + wc.lpszClassName],AX
       1020:0362 89 56 fc        MOV        word ptr [BP + wc+0x18],DX
       1020:0365 8d 46 e4        LEA        AX=>wc,[BP + -0x1c]
       1020:0368 8c d2           MOV        DX,SS
       1020:036a 52              PUSH       DX
       1020:036b 50              PUSH       AX
       1020:036c 9a d0 01        CALLF      USER::RegisterClass                              ATOM RegisterClass(WNDCLASS * pa
                 f8 14
       1020:0371 3d 00 00        CMP        AX,0x0
       1020:0374 74 03           JZ         LAB_1020_0379
       1020:0376 e9 06 00        JMP        LAB_1020_037f
                             LAB_1020_0379                                   XREF[1]:     1020:0374(j)  
       1020:0379 b8 00 00        MOV        AX,0x0
       1020:037c e9 06 00        JMP        LAB_1020_0385
                             LAB_1020_037f                                   XREF[1]:     1020:0376(j)  
       1020:037f b8 01 00        MOV        AX,0x1
       1020:0382 e9 00 00        JMP        LAB_1020_0385
                             LAB_1020_0385                                   XREF[12]:    1020:0073(j), 1020:00c2(j), 
                                                                                          1020:0102(j), 1020:0142(j), 
                                                                                          1020:0182(j), 1020:01c7(j), 
                                                                                          1020:020c(j), 1020:0251(j), 
                                                                                          1020:0296(j), 1020:0309(j), 
                                                                                          1020:037c(j), 1020:0382(j)  
       1020:0385 5f              POP        DI
       1020:0386 5e              POP        SI
       1020:0387 8b e5           MOV        SP,BP
       1020:0389 5d              POP        BP
       1020:038a cb              RETF
             assume CS = <UNKNOWN>
       1020:038b 90              ??         90h
```