rule win_unidentified_092_auto {

    meta:
        atk_type = "win.unidentified_092."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_092."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_092"
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
        $sequence_0 = { c78520ffffff00000000 c68510ffffff00 83f810 7241 8b8df8feffff 40 3d00100000 }
            // n = 7, score = 100
            //   c78520ffffff00000000     | mov    dword ptr [ebp - 0xe0], 0
            //   c68510ffffff00       | mov                 byte ptr [ebp - 0xf0], 0
            //   83f810               | cmp                 eax, 0x10
            //   7241                 | jb                  0x43
            //   8b8df8feffff         | mov                 ecx, dword ptr [ebp - 0x108]
            //   40                   | inc                 eax
            //   3d00100000           | cmp                 eax, 0x1000

        $sequence_1 = { 723f 8b4c2464 40 3d00100000 722a f6c11f 0f850b010000 }
            // n = 7, score = 100
            //   723f                 | jb                  0x41
            //   8b4c2464             | mov                 ecx, dword ptr [esp + 0x64]
            //   40                   | inc                 eax
            //   3d00100000           | cmp                 eax, 0x1000
            //   722a                 | jb                  0x2c
            //   f6c11f               | test                cl, 0x1f
            //   0f850b010000         | jne                 0x111

        $sequence_2 = { 33f1 8b7df8 0375a4 8bd3 8b5dfc f7d2 8b4de8 }
            // n = 7, score = 100
            //   33f1                 | xor                 esi, ecx
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]
            //   0375a4               | add                 esi, dword ptr [ebp - 0x5c]
            //   8bd3                 | mov                 edx, ebx
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   f7d2                 | not                 edx
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]

        $sequence_3 = { 8b41fc 3bc1 0f83de020000 2bc8 83f904 0f82d3020000 83f923 }
            // n = 7, score = 100
            //   8b41fc               | mov                 eax, dword ptr [ecx - 4]
            //   3bc1                 | cmp                 eax, ecx
            //   0f83de020000         | jae                 0x2e4
            //   2bc8                 | sub                 ecx, eax
            //   83f904               | cmp                 ecx, 4
            //   0f82d3020000         | jb                  0x2d9
            //   83f923               | cmp                 ecx, 0x23

        $sequence_4 = { 0155ec c1c107 33f1 8bcb 8bd3 }
            // n = 5, score = 100
            //   0155ec               | add                 dword ptr [ebp - 0x14], edx
            //   c1c107               | rol                 ecx, 7
            //   33f1                 | xor                 esi, ecx
            //   8bcb                 | mov                 ecx, ebx
            //   8bd3                 | mov                 edx, ebx

        $sequence_5 = { 56 52 50 8b08 ff511c c745fcffffffff 83ceff }
            // n = 7, score = 100
            //   56                   | push                esi
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff511c               | call                dword ptr [ecx + 0x1c]
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   83ceff               | or                  esi, 0xffffffff

        $sequence_6 = { 8d8558ffffff 50 0f118568ffffff ffd3 c645fc03 83ec10 }
            // n = 6, score = 100
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]
            //   50                   | push                eax
            //   0f118568ffffff       | movups              xmmword ptr [ebp - 0x98], xmm0
            //   ffd3                 | call                ebx
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   83ec10               | sub                 esp, 0x10

        $sequence_7 = { 8bc3 c1c007 8bcb 33d0 897508 f7d1 8bc3 }
            // n = 7, score = 100
            //   8bc3                 | mov                 eax, ebx
            //   c1c007               | rol                 eax, 7
            //   8bcb                 | mov                 ecx, ebx
            //   33d0                 | xor                 edx, eax
            //   897508               | mov                 dword ptr [ebp + 8], esi
            //   f7d1                 | not                 ecx
            //   8bc3                 | mov                 eax, ebx

        $sequence_8 = { 83ee01 75e9 8b85e4fbffff 83f814 }
            // n = 4, score = 100
            //   83ee01               | sub                 esi, 1
            //   75e9                 | jne                 0xffffffeb
            //   8b85e4fbffff         | mov                 eax, dword ptr [ebp - 0x41c]
            //   83f814               | cmp                 eax, 0x14

        $sequence_9 = { 50 56 ffd3 85c0 7f38 68???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7f38                 | jg                  0x3a
            //   68????????           |                     

    condition:
        7 of them and filesize < 10202112
}