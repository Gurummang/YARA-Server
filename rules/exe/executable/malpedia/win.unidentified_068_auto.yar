rule win_unidentified_068_auto {

    meta:
        atk_type = "win.unidentified_068."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_068."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_068"
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
        $sequence_0 = { 75ee 394624 7417 50 8bce e8???????? }
            // n = 6, score = 100
            //   75ee                 | jne                 0xfffffff0
            //   394624               | cmp                 dword ptr [esi + 0x24], eax
            //   7417                 | je                  0x19
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_1 = { 43 8bc8 3bde 72e6 8b75e0 8b5df4 8b55f8 }
            // n = 7, score = 100
            //   43                   | inc                 ebx
            //   8bc8                 | mov                 ecx, eax
            //   3bde                 | cmp                 ebx, esi
            //   72e6                 | jb                  0xffffffe8
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]
            //   8b5df4               | mov                 ebx, dword ptr [ebp - 0xc]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]

        $sequence_2 = { 85ff 741b 8b4674 ff7514 8b0c98 83c118 e8???????? }
            // n = 7, score = 100
            //   85ff                 | test                edi, edi
            //   741b                 | je                  0x1d
            //   8b4674               | mov                 eax, dword ptr [esi + 0x74]
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8b0c98               | mov                 ecx, dword ptr [eax + ebx*4]
            //   83c118               | add                 ecx, 0x18
            //   e8????????           |                     

        $sequence_3 = { 59 57 8bd8 c745fc04000000 8d45fc 50 53 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   57                   | push                edi
            //   8bd8                 | mov                 ebx, eax
            //   c745fc04000000       | mov                 dword ptr [ebp - 4], 4
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_4 = { 7406 8b08 50 ff5108 885d94 895df0 8d4df0 }
            // n = 7, score = 100
            //   7406                 | je                  8
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   885d94               | mov                 byte ptr [ebp - 0x6c], bl
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   8d4df0               | lea                 ecx, [ebp - 0x10]

        $sequence_5 = { 8d5648 8d4d88 e8???????? 59 83781408 7202 8b00 }
            // n = 7, score = 100
            //   8d5648               | lea                 edx, [esi + 0x48]
            //   8d4d88               | lea                 ecx, [ebp - 0x78]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83781408             | cmp                 dword ptr [eax + 0x14], 8
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_6 = { 660f13442450 8b4c2454 894c2458 8b4c2450 894c2450 8b4c2464 894c2428 }
            // n = 7, score = 100
            //   660f13442450         | movlpd              qword ptr [esp + 0x50], xmm0
            //   8b4c2454             | mov                 ecx, dword ptr [esp + 0x54]
            //   894c2458             | mov                 dword ptr [esp + 0x58], ecx
            //   8b4c2450             | mov                 ecx, dword ptr [esp + 0x50]
            //   894c2450             | mov                 dword ptr [esp + 0x50], ecx
            //   8b4c2464             | mov                 ecx, dword ptr [esp + 0x64]
            //   894c2428             | mov                 dword ptr [esp + 0x28], ecx

        $sequence_7 = { d1f9 6a41 5f 894df0 8b34cd18aa4400 8b4d08 6a5a }
            // n = 7, score = 100
            //   d1f9                 | sar                 ecx, 1
            //   6a41                 | push                0x41
            //   5f                   | pop                 edi
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b34cd18aa4400       | mov                 esi, dword ptr [ecx*8 + 0x44aa18]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   6a5a                 | push                0x5a

        $sequence_8 = { 72ba 33f6 81fb10000020 0f45f3 85f6 7523 33db }
            // n = 7, score = 100
            //   72ba                 | jb                  0xffffffbc
            //   33f6                 | xor                 esi, esi
            //   81fb10000020         | cmp                 ebx, 0x20000010
            //   0f45f3               | cmovne              esi, ebx
            //   85f6                 | test                esi, esi
            //   7523                 | jne                 0x25
            //   33db                 | xor                 ebx, ebx

        $sequence_9 = { 8d4948 e8???????? 33c0 5d c20800 55 8bec }
            // n = 7, score = 100
            //   8d4948               | lea                 ecx, [ecx + 0x48]
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

    condition:
        7 of them and filesize < 862208
}