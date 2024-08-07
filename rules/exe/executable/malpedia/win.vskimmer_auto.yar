rule win_vskimmer_auto {

    meta:
        atk_type = "win.vskimmer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.vskimmer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vskimmer"
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
        $sequence_0 = { 3bc3 7402 8bf0 8bd6 f7da 8a07 }
            // n = 6, score = 100
            //   3bc3                 | cmp                 eax, ebx
            //   7402                 | je                  4
            //   8bf0                 | mov                 esi, eax
            //   8bd6                 | mov                 edx, esi
            //   f7da                 | neg                 edx
            //   8a07                 | mov                 al, byte ptr [edi]

        $sequence_1 = { 68???????? 50 e8???????? 59 59 85c0 0f8445010000 }
            // n = 7, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   0f8445010000         | je                  0x14b

        $sequence_2 = { 33c0 0fbe84c188e54100 6a07 c1f804 59 }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   0fbe84c188e54100     | movsx               eax, byte ptr [ecx + eax*8 + 0x41e588]
            //   6a07                 | push                7
            //   c1f804               | sar                 eax, 4
            //   59                   | pop                 ecx

        $sequence_3 = { 75f8 ff36 e8???????? 59 8b4508 }
            // n = 5, score = 100
            //   75f8                 | jne                 0xfffffffa
            //   ff36                 | push                dword ptr [esi]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { 8b4508 8bf1 8b4d0c 8b7e04 }
            // n = 4, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bf1                 | mov                 esi, ecx
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b7e04               | mov                 edi, dword ptr [esi + 4]

        $sequence_5 = { 5e 5b c3 8b94c110010000 8bb110020000 8b44c108 2bc6 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8b94c110010000       | mov                 edx, dword ptr [ecx + eax*8 + 0x110]
            //   8bb110020000         | mov                 esi, dword ptr [ecx + 0x210]
            //   8b44c108             | mov                 eax, dword ptr [ecx + eax*8 + 8]
            //   2bc6                 | sub                 eax, esi

        $sequence_6 = { 3bd7 749c 8b8324020000 2580000000 0f95c0 0fb6c0 50 }
            // n = 7, score = 100
            //   3bd7                 | cmp                 edx, edi
            //   749c                 | je                  0xffffff9e
            //   8b8324020000         | mov                 eax, dword ptr [ebx + 0x224]
            //   2580000000           | and                 eax, 0x80
            //   0f95c0               | setne               al
            //   0fb6c0               | movzx               eax, al
            //   50                   | push                eax

        $sequence_7 = { 7e7b 8b460c ff36 03c7 50 }
            // n = 5, score = 100
            //   7e7b                 | jle                 0x7d
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   ff36                 | push                dword ptr [esi]
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax

        $sequence_8 = { 7413 c685b3fdffff01 3bf3 7408 8b451c 8906 }
            // n = 6, score = 100
            //   7413                 | je                  0x15
            //   c685b3fdffff01       | mov                 byte ptr [ebp - 0x24d], 1
            //   3bf3                 | cmp                 esi, ebx
            //   7408                 | je                  0xa
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_9 = { 83e803 0f846a010000 48 7439 48 742d 8b4508 }
            // n = 7, score = 100
            //   83e803               | sub                 eax, 3
            //   0f846a010000         | je                  0x170
            //   48                   | dec                 eax
            //   7439                 | je                  0x3b
            //   48                   | dec                 eax
            //   742d                 | je                  0x2f
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 376832
}