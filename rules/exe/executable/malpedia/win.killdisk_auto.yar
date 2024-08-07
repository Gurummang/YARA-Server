rule win_killdisk_auto {

    meta:
        atk_type = "win.killdisk."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.killdisk."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.killdisk"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8d4604 7204 8b08 eb02 8bc8 66891c51 }
            // n = 6, score = 100
            //   8d4604               | lea                 eax, [esi + 4]
            //   7204                 | jb                  6
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   eb02                 | jmp                 4
            //   8bc8                 | mov                 ecx, eax
            //   66891c51             | mov                 word ptr [ecx + edx*2], bx

        $sequence_1 = { 0f8424020000 8d4c245c b8???????? 8d642400 668b10 }
            // n = 5, score = 100
            //   0f8424020000         | je                  0x22a
            //   8d4c245c             | lea                 ecx, [esp + 0x5c]
            //   b8????????           |                     
            //   8d642400             | lea                 esp, [esp]
            //   668b10               | mov                 dx, word ptr [eax]

        $sequence_2 = { 881438 e8???????? 9c c6442408cf 894508 e9???????? }
            // n = 6, score = 100
            //   881438               | mov                 byte ptr [eax + edi], dl
            //   e8????????           |                     
            //   9c                   | pushfd              
            //   c6442408cf           | mov                 byte ptr [esp + 8], 0xcf
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   e9????????           |                     

        $sequence_3 = { 88742408 c70424ba7bbfa4 660fbae408 662dca11 e8???????? 881438 e8???????? }
            // n = 7, score = 100
            //   88742408             | mov                 byte ptr [esp + 8], dh
            //   c70424ba7bbfa4       | mov                 dword ptr [esp], 0xa4bf7bba
            //   660fbae408           | bt                  sp, 8
            //   662dca11             | sub                 ax, 0x11ca
            //   e8????????           |                     
            //   881438               | mov                 byte ptr [eax + edi], dl
            //   e8????????           |                     

        $sequence_4 = { 83c40c 68???????? 68e08fc201 e8???????? 8bf0 }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   68e08fc201           | push                0x1c28fe0
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { 8f44241c c64424148e c644240426 e8???????? 4e e8???????? 54 }
            // n = 7, score = 100
            //   8f44241c             | pop                 dword ptr [esp + 0x1c]
            //   c64424148e           | mov                 byte ptr [esp + 0x14], 0x8e
            //   c644240426           | mov                 byte ptr [esp + 4], 0x26
            //   e8????????           |                     
            //   4e                   | dec                 esi
            //   e8????????           |                     
            //   54                   | push                esp

        $sequence_6 = { c3 50 ff15???????? 8b8c24d41a0000 }
            // n = 4, score = 100
            //   c3                   | ret                 
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b8c24d41a0000       | mov                 ecx, dword ptr [esp + 0x1ad4]

        $sequence_7 = { 872d???????? 0fc1c2 89e2 66d3c9 66d3c0 }
            // n = 5, score = 100
            //   872d????????         |                     
            //   0fc1c2               | xadd                edx, eax
            //   89e2                 | mov                 edx, esp
            //   66d3c9               | ror                 cx, cl
            //   66d3c0               | rol                 ax, cl

        $sequence_8 = { e8???????? 84c0 751a a1???????? 50 6802000080 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   751a                 | jne                 0x1c
            //   a1????????           |                     
            //   50                   | push                eax
            //   6802000080           | push                0x80000002

        $sequence_9 = { b001 5e 59 c3 837f1800 7413 }
            // n = 6, score = 100
            //   b001                 | mov                 al, 1
            //   5e                   | pop                 esi
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   837f1800             | cmp                 dword ptr [edi + 0x18], 0
            //   7413                 | je                  0x15

        $sequence_10 = { e8???????? 83c420 6a00 8d442414 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   6a00                 | push                0
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_11 = { 46 66892c24 9c 8d64244c e9???????? 9c 9c }
            // n = 7, score = 100
            //   46                   | inc                 esi
            //   66892c24             | mov                 word ptr [esp], bp
            //   9c                   | pushfd              
            //   8d64244c             | lea                 esp, [esp + 0x4c]
            //   e9????????           |                     
            //   9c                   | pushfd              
            //   9c                   | pushfd              

        $sequence_12 = { 9c 8d642430 e9???????? ff742404 66894500 }
            // n = 5, score = 100
            //   9c                   | pushfd              
            //   8d642430             | lea                 esp, [esp + 0x30]
            //   e9????????           |                     
            //   ff742404             | push                dword ptr [esp + 4]
            //   66894500             | mov                 word ptr [ebp], ax

        $sequence_13 = { 8d642454 e9???????? 880424 8774242c 9c 68a12348dd e8???????? }
            // n = 7, score = 100
            //   8d642454             | lea                 esp, [esp + 0x54]
            //   e9????????           |                     
            //   880424               | mov                 byte ptr [esp], al
            //   8774242c             | xchg                dword ptr [esp + 0x2c], esi
            //   9c                   | pushfd              
            //   68a12348dd           | push                0xdd4823a1
            //   e8????????           |                     

        $sequence_14 = { 66897c240c 882c24 c64424044f 8d642454 e9???????? }
            // n = 5, score = 100
            //   66897c240c           | mov                 word ptr [esp + 0xc], di
            //   882c24               | mov                 byte ptr [esp], ch
            //   c64424044f           | mov                 byte ptr [esp + 4], 0x4f
            //   8d642454             | lea                 esp, [esp + 0x54]
            //   e9????????           |                     

        $sequence_15 = { 56 e8???????? c1f805 56 8d3c85a098c201 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   c1f805               | sar                 eax, 5
            //   56                   | push                esi
            //   8d3c85a098c201       | lea                 edi, [eax*4 + 0x1c298a0]

    condition:
        7 of them and filesize < 10817536
}