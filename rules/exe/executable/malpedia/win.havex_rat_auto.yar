rule win_havex_rat_auto {

    meta:
        atk_type = "win.havex_rat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.havex_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.havex_rat"
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
        $sequence_0 = { 134304 8937 ebd8 8917 c74704ffffff7f 8bc7 5e }
            // n = 7, score = 100
            //   134304               | adc                 eax, dword ptr [ebx + 4]
            //   8937                 | mov                 dword ptr [edi], esi
            //   ebd8                 | jmp                 0xffffffda
            //   8917                 | mov                 dword ptr [edi], edx
            //   c74704ffffff7f       | mov                 dword ptr [edi + 4], 0x7fffffff
            //   8bc7                 | mov                 eax, edi
            //   5e                   | pop                 esi

        $sequence_1 = { 0fb7c0 b9ffff0000 663bc8 7576 834dec04 33f6 3975ec }
            // n = 7, score = 100
            //   0fb7c0               | movzx               eax, ax
            //   b9ffff0000           | mov                 ecx, 0xffff
            //   663bc8               | cmp                 cx, ax
            //   7576                 | jne                 0x78
            //   834dec04             | or                  dword ptr [ebp - 0x14], 4
            //   33f6                 | xor                 esi, esi
            //   3975ec               | cmp                 dword ptr [ebp - 0x14], esi

        $sequence_2 = { e8???????? 8bcf c745dcac230510 e8???????? e8???????? c20400 6a30 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bcf                 | mov                 ecx, edi
            //   c745dcac230510       | mov                 dword ptr [ebp - 0x24], 0x100523ac
            //   e8????????           |                     
            //   e8????????           |                     
            //   c20400               | ret                 4
            //   6a30                 | push                0x30

        $sequence_3 = { 297d78 c78580000000feffffff 29bd80000000 8d4417ff 660fb67801 66c1e908 66c1e708 }
            // n = 7, score = 100
            //   297d78               | sub                 dword ptr [ebp + 0x78], edi
            //   c78580000000feffffff     | mov    dword ptr [ebp + 0x80], 0xfffffffe
            //   29bd80000000         | sub                 dword ptr [ebp + 0x80], edi
            //   8d4417ff             | lea                 eax, [edi + edx - 1]
            //   660fb67801           | movzx               di, byte ptr [eax + 1]
            //   66c1e908             | shr                 cx, 8
            //   66c1e708             | shl                 di, 8

        $sequence_4 = { 56 8d8550feffff e8???????? ff757c 8d8550feffff ff7574 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d8550feffff         | lea                 eax, [ebp - 0x1b0]
            //   e8????????           |                     
            //   ff757c               | push                dword ptr [ebp + 0x7c]
            //   8d8550feffff         | lea                 eax, [ebp - 0x1b0]
            //   ff7574               | push                dword ptr [ebp + 0x74]

        $sequence_5 = { 8b7d08 59 59 3bc3 7404 8938 eb02 }
            // n = 7, score = 100
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   3bc3                 | cmp                 eax, ebx
            //   7404                 | je                  6
            //   8938                 | mov                 dword ptr [eax], edi
            //   eb02                 | jmp                 4

        $sequence_6 = { 84c0 0f854bffffff 33f6 e9???????? 8bb5c8fdffff e9???????? 55 }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   0f854bffffff         | jne                 0xffffff51
            //   33f6                 | xor                 esi, esi
            //   e9????????           |                     
            //   8bb5c8fdffff         | mov                 esi, dword ptr [ebp - 0x238]
            //   e9????????           |                     
            //   55                   | push                ebp

        $sequence_7 = { 740a 6683f85c 0f858e000000 83c8ff 5f 5e 5b }
            // n = 7, score = 100
            //   740a                 | je                  0xc
            //   6683f85c             | cmp                 ax, 0x5c
            //   0f858e000000         | jne                 0x94
            //   83c8ff               | or                  eax, 0xffffffff
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_8 = { 68???????? 8d4c2414 e8???????? 8d442410 50 8d4c2430 897c2464 }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   e8????????           |                     
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   8d4c2430             | lea                 ecx, [esp + 0x30]
            //   897c2464             | mov                 dword ptr [esp + 0x64], edi

        $sequence_9 = { 5b c9 c3 55 8bec 8b4614 83ec10 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]
            //   83ec10               | sub                 esp, 0x10

    condition:
        7 of them and filesize < 892928
}