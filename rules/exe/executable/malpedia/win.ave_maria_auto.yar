rule win_ave_maria_auto {

    meta:
        atk_type = "win.ave_maria."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ave_maria."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria"
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
        $sequence_0 = { 8b07 ff740610 8d4614 50 8d45f8 50 }
            // n = 6, score = 400
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   ff740610             | push                dword ptr [esi + eax + 0x10]
            //   8d4614               | lea                 eax, [esi + 0x14]
            //   50                   | push                eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax

        $sequence_1 = { 52 8b08 6a01 50 ff510c 85c0 74c1 }
            // n = 7, score = 400
            //   52                   | push                edx
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   ff510c               | call                dword ptr [ecx + 0xc]
            //   85c0                 | test                eax, eax
            //   74c1                 | je                  0xffffffc3

        $sequence_2 = { 6a0a 03c1 59 8bf8 f3a5 8d4d30 }
            // n = 6, score = 400
            //   6a0a                 | push                0xa
            //   03c1                 | add                 eax, ecx
            //   59                   | pop                 ecx
            //   8bf8                 | mov                 edi, eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8d4d30               | lea                 ecx, [ebp + 0x30]

        $sequence_3 = { 0f57c0 c745e015000000 50 8d4de0 0f1145e8 e8???????? 8bc8 }
            // n = 7, score = 400
            //   0f57c0               | xorps               xmm0, xmm0
            //   c745e015000000       | mov                 dword ptr [ebp - 0x20], 0x15
            //   50                   | push                eax
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   0f1145e8             | movups              xmmword ptr [ebp - 0x18], xmm0
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_4 = { 803800 7509 33c0 5b c3 33c0 40 }
            // n = 7, score = 400
            //   803800               | cmp                 byte ptr [eax], 0
            //   7509                 | jne                 0xb
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax

        $sequence_5 = { 8bc7 99 2bc1 8bcf 1bd6 52 50 }
            // n = 7, score = 400
            //   8bc7                 | mov                 eax, edi
            //   99                   | cdq                 
            //   2bc1                 | sub                 eax, ecx
            //   8bcf                 | mov                 ecx, edi
            //   1bd6                 | sbb                 edx, esi
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_6 = { ff500c 8b06 68???????? ff37 8b08 }
            // n = 5, score = 400
            //   ff500c               | call                dword ptr [eax + 0xc]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   68????????           |                     
            //   ff37                 | push                dword ptr [edi]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_7 = { 51 54 8bce e8???????? 8b4d08 e8???????? 83c410 }
            // n = 7, score = 400
            //   51                   | push                ecx
            //   54                   | push                esp
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_8 = { 300431 41 3bcf 7ced 5f 8bc6 5e }
            // n = 7, score = 400
            //   300431               | xor                 byte ptr [ecx + esi], al
            //   41                   | inc                 ecx
            //   3bcf                 | cmp                 ecx, edi
            //   7ced                 | jl                  0xffffffef
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi

        $sequence_9 = { 83ec18 53 8bd9 56 57 895df8 }
            // n = 6, score = 400
            //   83ec18               | sub                 esp, 0x18
            //   53                   | push                ebx
            //   8bd9                 | mov                 ebx, ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   895df8               | mov                 dword ptr [ebp - 8], ebx

    condition:
        7 of them and filesize < 237568
}