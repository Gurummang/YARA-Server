rule win_wpbrutebot_auto {

    meta:
        atk_type = "win.wpbrutebot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.wpbrutebot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wpbrutebot"
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
        $sequence_0 = { 894f54 897758 89775c e9???????? 85c9 7515 c7475003000000 }
            // n = 7, score = 100
            //   894f54               | mov                 dword ptr [edi + 0x54], ecx
            //   897758               | mov                 dword ptr [edi + 0x58], esi
            //   89775c               | mov                 dword ptr [edi + 0x5c], esi
            //   e9????????           |                     
            //   85c9                 | test                ecx, ecx
            //   7515                 | jne                 0x17
            //   c7475003000000       | mov                 dword ptr [edi + 0x50], 3

        $sequence_1 = { f7472c00010000 b35d 7411 8b4730 6a5d 8b4804 8b01 }
            // n = 7, score = 100
            //   f7472c00010000       | test                dword ptr [edi + 0x2c], 0x100
            //   b35d                 | mov                 bl, 0x5d
            //   7411                 | je                  0x13
            //   8b4730               | mov                 eax, dword ptr [edi + 0x30]
            //   6a5d                 | push                0x5d
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_2 = { f6044dc81e5e0002 7410 8bc1 ba01000000 83f020 85d2 0f44c1 }
            // n = 7, score = 100
            //   f6044dc81e5e0002     | test                byte ptr [ecx*2 + 0x5e1ec8], 2
            //   7410                 | je                  0x12
            //   8bc1                 | mov                 eax, ecx
            //   ba01000000           | mov                 edx, 1
            //   83f020               | xor                 eax, 0x20
            //   85d2                 | test                edx, edx
            //   0f44c1               | cmove               eax, ecx

        $sequence_3 = { c645fc04 8d8dfcf4ffff e8???????? 68???????? 8bd0 c645fc05 8d8d14f5ffff }
            // n = 7, score = 100
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   8d8dfcf4ffff         | lea                 ecx, [ebp - 0xb04]
            //   e8????????           |                     
            //   68????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   8d8d14f5ffff         | lea                 ecx, [ebp - 0xaec]

        $sequence_4 = { ff742420 8b7a08 037c2420 89442448 c744244c01000000 897c2450 8b4a08 }
            // n = 7, score = 100
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   8b7a08               | mov                 edi, dword ptr [edx + 8]
            //   037c2420             | add                 edi, dword ptr [esp + 0x20]
            //   89442448             | mov                 dword ptr [esp + 0x48], eax
            //   c744244c01000000     | mov                 dword ptr [esp + 0x4c], 1
            //   897c2450             | mov                 dword ptr [esp + 0x50], edi
            //   8b4a08               | mov                 ecx, dword ptr [edx + 8]

        $sequence_5 = { c781f0050000bfe45900 5b 83c408 c3 5f 5e 5d }
            // n = 7, score = 100
            //   c781f0050000bfe45900     | mov    dword ptr [ecx + 0x5f0], 0x59e4bf
            //   5b                   | pop                 ebx
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_6 = { 7228 8bb504ffffff 8d8504ffffff 50 8bc8 e8???????? 8b8518ffffff }
            // n = 7, score = 100
            //   7228                 | jb                  0x2a
            //   8bb504ffffff         | mov                 esi, dword ptr [ebp - 0xfc]
            //   8d8504ffffff         | lea                 eax, [ebp - 0xfc]
            //   50                   | push                eax
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b8518ffffff         | mov                 eax, dword ptr [ebp - 0xe8]

        $sequence_7 = { 8b44245c a802 b800000000 0f45d8 895c241c 85f6 7410 }
            // n = 7, score = 100
            //   8b44245c             | mov                 eax, dword ptr [esp + 0x5c]
            //   a802                 | test                al, 2
            //   b800000000           | mov                 eax, 0
            //   0f45d8               | cmovne              ebx, eax
            //   895c241c             | mov                 dword ptr [esp + 0x1c], ebx
            //   85f6                 | test                esi, esi
            //   7410                 | je                  0x12

        $sequence_8 = { f7e9 d1fa 8bc2 c1e81f 03c2 83f801 762b }
            // n = 7, score = 100
            //   f7e9                 | imul                ecx
            //   d1fa                 | sar                 edx, 1
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03c2                 | add                 eax, edx
            //   83f801               | cmp                 eax, 1
            //   762b                 | jbe                 0x2d

        $sequence_9 = { ffb7ec0c0000 6a01 53 e8???????? 8be8 83c410 }
            // n = 6, score = 100
            //   ffb7ec0c0000         | push                dword ptr [edi + 0xcec]
            //   6a01                 | push                1
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8be8                 | mov                 ebp, eax
            //   83c410               | add                 esp, 0x10

    condition:
        7 of them and filesize < 5134336
}