rule win_oski_auto {

    meta:
        atk_type = "win.oski."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.oski."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oski"
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
        $sequence_0 = { 50 a1???????? 50 8d8df0feffff 51 e8???????? }
            // n = 6, score = 1100
            //   50                   | push                eax
            //   a1????????           |                     
            //   50                   | push                eax
            //   8d8df0feffff         | lea                 ecx, [ebp - 0x110]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_1 = { 25ff7f0000 c3 8bff 55 8bec 83ec14 ff7510 }
            // n = 7, score = 1000
            //   25ff7f0000           | and                 eax, 0x7fff
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec14               | sub                 esp, 0x14
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_2 = { e8???????? 83c40c e8???????? 50 a1???????? 50 }
            // n = 6, score = 900
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     
            //   50                   | push                eax
            //   a1????????           |                     
            //   50                   | push                eax

        $sequence_3 = { 8975f0 e8???????? cc 8bff 55 8bec 8b550c }
            // n = 7, score = 900
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   e8????????           |                     
            //   cc                   | int3                
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_4 = { 7408 39b5acfeffff 7787 6803010000 8d95edfeffff 56 }
            // n = 6, score = 800
            //   7408                 | je                  0xa
            //   39b5acfeffff         | cmp                 dword ptr [ebp - 0x154], esi
            //   7787                 | ja                  0xffffff89
            //   6803010000           | push                0x103
            //   8d95edfeffff         | lea                 edx, [ebp - 0x113]
            //   56                   | push                esi

        $sequence_5 = { 83431810 66898568fbffff 8b4314 85c0 7577 8b8d84fbffff 51 }
            // n = 7, score = 800
            //   83431810             | add                 dword ptr [ebx + 0x18], 0x10
            //   66898568fbffff       | mov                 word ptr [ebp - 0x498], ax
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]
            //   85c0                 | test                eax, eax
            //   7577                 | jne                 0x79
            //   8b8d84fbffff         | mov                 ecx, dword ptr [ebp - 0x47c]
            //   51                   | push                ecx

        $sequence_6 = { 6a00 6a1a 6a00 8985eceeffff 898df0eeffff }
            // n = 5, score = 800
            //   6a00                 | push                0
            //   6a1a                 | push                0x1a
            //   6a00                 | push                0
            //   8985eceeffff         | mov                 dword ptr [ebp - 0x1114], eax
            //   898df0eeffff         | mov                 dword ptr [ebp - 0x1110], ecx

        $sequence_7 = { 53 68???????? 8d8de4feffff 51 53 }
            // n = 5, score = 800
            //   53                   | push                ebx
            //   68????????           |                     
            //   8d8de4feffff         | lea                 ecx, [ebp - 0x11c]
            //   51                   | push                ecx
            //   53                   | push                ebx

        $sequence_8 = { e8???????? 83c404 56 8d85ecfeffff 50 8d8dd0fcffff }
            // n = 6, score = 800
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   56                   | push                esi
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   50                   | push                eax
            //   8d8dd0fcffff         | lea                 ecx, [ebp - 0x330]

        $sequence_9 = { f3c3 e9???????? 8bff 55 8bec 83ec1c a1???????? }
            // n = 7, score = 800
            //   f3c3                 | ret                 
            //   e9????????           |                     
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec1c               | sub                 esp, 0x1c
            //   a1????????           |                     

        $sequence_10 = { e8???????? 83c404 8b0d???????? 51 ff15???????? a3???????? 833d????????00 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   a3????????           |                     
            //   833d????????00       |                     

        $sequence_11 = { 8b5508 52 a1???????? 50 8d8de8fdffff }
            // n = 5, score = 400
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   a1????????           |                     
            //   50                   | push                eax
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]

        $sequence_12 = { 83c404 8b55f8 8955f4 8b45f4 50 e8???????? }
            // n = 6, score = 400
            //   83c404               | add                 esp, 4
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_13 = { 50 8d4df8 51 6800020000 8b55f4 52 ff15???????? }
            // n = 7, score = 400
            //   50                   | push                eax
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   51                   | push                ecx
            //   6800020000           | push                0x200
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_14 = { 6a00 e8???????? 83c40c 8985e4fdffff }
            // n = 4, score = 400
            //   6a00                 | push                0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8985e4fdffff         | mov                 dword ptr [ebp - 0x21c], eax

        $sequence_15 = { 8d55f4 52 6a00 68???????? ff15???????? 8945f0 }
            // n = 6, score = 400
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   52                   | push                edx
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff15????????         |                     
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_16 = { 83c220 52 6a00 6a00 ff15???????? }
            // n = 5, score = 400
            //   83c220               | add                 edx, 0x20
            //   52                   | push                edx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 423936
}