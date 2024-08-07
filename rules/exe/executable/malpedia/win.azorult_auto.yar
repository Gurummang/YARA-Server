rule win_azorult_auto {

    meta:
        atk_type = "win.azorult."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.azorult."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.azorult"
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
        $sequence_0 = { 50 ba???????? 8d45e8 e8???????? 8d45e4 8b55f8 8a543201 }
            // n = 7, score = 1200
            //   50                   | push                eax
            //   ba????????           |                     
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   e8????????           |                     
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8a543201             | mov                 dl, byte ptr [edx + esi + 1]

        $sequence_1 = { e8???????? 56 8d85a0fdffff b9???????? }
            // n = 4, score = 1200
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d85a0fdffff         | lea                 eax, [ebp - 0x260]
            //   b9????????           |                     

        $sequence_2 = { b9???????? 8b55fc e8???????? 8b859cfdffff e8???????? }
            // n = 5, score = 1200
            //   b9????????           |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b859cfdffff         | mov                 eax, dword ptr [ebp - 0x264]
            //   e8????????           |                     

        $sequence_3 = { b80f270000 e8???????? 8945f8 8d55f4 8bc3 }
            // n = 5, score = 1200
            //   b80f270000           | mov                 eax, 0x270f
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   8bc3                 | mov                 eax, ebx

        $sequence_4 = { b80f270000 e8???????? 8bf0 b80f270000 }
            // n = 4, score = 1200
            //   b80f270000           | mov                 eax, 0x270f
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   b80f270000           | mov                 eax, 0x270f

        $sequence_5 = { 7518 56 8b45fc e8???????? 8bc8 8d5301 }
            // n = 6, score = 1200
            //   7518                 | jne                 0x1a
            //   56                   | push                esi
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   8d5301               | lea                 edx, [ebx + 1]

        $sequence_6 = { b80f270000 e8???????? 8bd8 b80f270000 }
            // n = 4, score = 1200
            //   b80f270000           | mov                 eax, 0x270f
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   b80f270000           | mov                 eax, 0x270f

        $sequence_7 = { ba03000000 e8???????? 8d858cfdffff e8???????? }
            // n = 4, score = 1200
            //   ba03000000           | mov                 edx, 3
            //   e8????????           |                     
            //   8d858cfdffff         | lea                 eax, [ebp - 0x274]
            //   e8????????           |                     

        $sequence_8 = { 7506 ff05???????? 56 e8???????? 59 }
            // n = 5, score = 900
            //   7506                 | jne                 8
            //   ff05????????         |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_9 = { e8???????? 59 8b45f4 40 }
            // n = 4, score = 600
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   40                   | inc                 eax

        $sequence_10 = { 50 e8???????? 59 8bd8 33c0 }
            // n = 5, score = 600
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bd8                 | mov                 ebx, eax
            //   33c0                 | xor                 eax, eax

        $sequence_11 = { 85db 7404 8bc3 eb07 }
            // n = 4, score = 500
            //   85db                 | test                ebx, ebx
            //   7404                 | je                  6
            //   8bc3                 | mov                 eax, ebx
            //   eb07                 | jmp                 9

        $sequence_12 = { 011f 59 8bc3 c1e003 01866caf0100 }
            // n = 5, score = 200
            //   011f                 | add                 dword ptr [edi], ebx
            //   59                   | pop                 ecx
            //   8bc3                 | mov                 eax, ebx
            //   c1e003               | shl                 eax, 3
            //   01866caf0100         | add                 dword ptr [esi + 0x1af6c], eax

        $sequence_13 = { 014f18 8b4714 85c0 0f854e010000 }
            // n = 4, score = 200
            //   014f18               | add                 dword ptr [edi + 0x18], ecx
            //   8b4714               | mov                 eax, dword ptr [edi + 0x14]
            //   85c0                 | test                eax, eax
            //   0f854e010000         | jne                 0x154

        $sequence_14 = { 014110 5f 5e 5b }
            // n = 4, score = 200
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_15 = { 01590c 8b45f0 014110 5f }
            // n = 4, score = 200
            //   01590c               | add                 dword ptr [ecx + 0xc], ebx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 1753088
}