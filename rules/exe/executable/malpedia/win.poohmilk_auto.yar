rule win_poohmilk_auto {

    meta:
        atk_type = "win.poohmilk."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.poohmilk."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poohmilk"
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
        $sequence_0 = { d3eb 2bf1 8b0c850c344100 014c822c 40 89856cffffff e9???????? }
            // n = 7, score = 200
            //   d3eb                 | shr                 ebx, cl
            //   2bf1                 | sub                 esi, ecx
            //   8b0c850c344100       | mov                 ecx, dword ptr [eax*4 + 0x41340c]
            //   014c822c             | add                 dword ptr [edx + eax*4 + 0x2c], ecx
            //   40                   | inc                 eax
            //   89856cffffff         | mov                 dword ptr [ebp - 0x94], eax
            //   e9????????           |                     

        $sequence_1 = { 898560f3ffff c705????????00000000 ffd7 8d8dccf7ffff 51 }
            // n = 5, score = 200
            //   898560f3ffff         | mov                 dword ptr [ebp - 0xca0], eax
            //   c705????????00000000     |     
            //   ffd7                 | call                edi
            //   8d8dccf7ffff         | lea                 ecx, [ebp - 0x834]
            //   51                   | push                ecx

        $sequence_2 = { 0301 eb02 33c0 8b4d08 85c9 7406 }
            // n = 6, score = 200
            //   0301                 | add                 eax, dword ptr [ecx]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8

        $sequence_3 = { 898d74d2ffff 898d78d2ffff 3bd9 7417 3bc1 7513 33c0 }
            // n = 7, score = 200
            //   898d74d2ffff         | mov                 dword ptr [ebp - 0x2d8c], ecx
            //   898d78d2ffff         | mov                 dword ptr [ebp - 0x2d88], ecx
            //   3bd9                 | cmp                 ebx, ecx
            //   7417                 | je                  0x19
            //   3bc1                 | cmp                 eax, ecx
            //   7513                 | jne                 0x15
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 83ffff 0f8410010000 53 8b1d???????? 6a02 }
            // n = 5, score = 200
            //   83ffff               | cmp                 edi, -1
            //   0f8410010000         | je                  0x116
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   6a02                 | push                2

        $sequence_5 = { 8bd6 e8???????? 33c9 3b85a4fdffff 5f }
            // n = 5, score = 200
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   3b85a4fdffff         | cmp                 eax, dword ptr [ebp - 0x25c]
            //   5f                   | pop                 edi

        $sequence_6 = { 85c0 0f8499000000 68???????? 8d842424020000 50 ffd6 8b4c2410 }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   0f8499000000         | je                  0x9f
            //   68????????           |                     
            //   8d842424020000       | lea                 eax, [esp + 0x224]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]

        $sequence_7 = { 23fb d3eb 0fbe8a10344100 03f9 }
            // n = 4, score = 200
            //   23fb                 | and                 edi, ebx
            //   d3eb                 | shr                 ebx, cl
            //   0fbe8a10344100       | movsx               ecx, byte ptr [edx + 0x413410]
            //   03f9                 | add                 edi, ecx

        $sequence_8 = { 5e c21000 8bff 55 8bec 8b4d0c }
            // n = 6, score = 200
            //   5e                   | pop                 esi
            //   c21000               | ret                 0x10
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_9 = { 8b4710 8b4e28 53 52 8b5624 }
            // n = 5, score = 200
            //   8b4710               | mov                 eax, dword ptr [edi + 0x10]
            //   8b4e28               | mov                 ecx, dword ptr [esi + 0x28]
            //   53                   | push                ebx
            //   52                   | push                edx
            //   8b5624               | mov                 edx, dword ptr [esi + 0x24]

    condition:
        7 of them and filesize < 245760
}