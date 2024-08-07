rule win_amadey_auto {

    meta:
        atk_type = "win.amadey."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.amadey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey"
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
        $sequence_0 = { ebb0 b8???????? 83c410 5b }
            // n = 4, score = 700
            //   ebb0                 | jmp                 0xffffffb2
            //   b8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   5b                   | pop                 ebx

        $sequence_1 = { e8???????? 89c2 8b45f4 89d1 ba00000000 f7f1 }
            // n = 6, score = 700
            //   e8????????           |                     
            //   89c2                 | mov                 edx, eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   89d1                 | mov                 ecx, edx
            //   ba00000000           | mov                 edx, 0
            //   f7f1                 | div                 ecx

        $sequence_2 = { c744240805000000 c744240402000000 890424 e8???????? }
            // n = 4, score = 700
            //   c744240805000000     | mov                 dword ptr [esp + 8], 5
            //   c744240402000000     | mov                 dword ptr [esp + 4], 2
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     

        $sequence_3 = { c9 c3 55 89e5 81ecc8010000 }
            // n = 5, score = 700
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   81ecc8010000         | sub                 esp, 0x1c8

        $sequence_4 = { c70424???????? e8???????? 8b45fc 89442408 c7442404???????? 8b4508 890424 }
            // n = 7, score = 700
            //   c70424????????       |                     
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   c7442404????????     |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_5 = { c744240800020000 8d85f8fdffff 89442404 891424 e8???????? 83ec20 }
            // n = 6, score = 700
            //   c744240800020000     | mov                 dword ptr [esp + 8], 0x200
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   891424               | mov                 dword ptr [esp], edx
            //   e8????????           |                     
            //   83ec20               | sub                 esp, 0x20

        $sequence_6 = { c70424???????? e8???????? 890424 e8???????? 84c0 7407 c745fc05000000 }
            // n = 7, score = 700
            //   c70424????????       |                     
            //   e8????????           |                     
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7407                 | je                  9
            //   c745fc05000000       | mov                 dword ptr [ebp - 4], 5

        $sequence_7 = { 83ec04 8945f4 837df400 7454 8b4508 890424 }
            // n = 6, score = 700
            //   83ec04               | sub                 esp, 4
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7454                 | je                  0x56
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_8 = { 83fa10 722f 8b8d78feffff 42 }
            // n = 4, score = 600
            //   83fa10               | cmp                 edx, 0x10
            //   722f                 | jb                  0x31
            //   8b8d78feffff         | mov                 ecx, dword ptr [ebp - 0x188]
            //   42                   | inc                 edx

        $sequence_9 = { 8b8d78feffff 42 8bc1 81fa00100000 7214 8b49fc }
            // n = 6, score = 600
            //   8b8d78feffff         | mov                 ecx, dword ptr [ebp - 0x188]
            //   42                   | inc                 edx
            //   8bc1                 | mov                 eax, ecx
            //   81fa00100000         | cmp                 edx, 0x1000
            //   7214                 | jb                  0x16
            //   8b49fc               | mov                 ecx, dword ptr [ecx - 4]

        $sequence_10 = { 68???????? e8???????? 8d4dcc e8???????? 83c418 }
            // n = 5, score = 600
            //   68????????           |                     
            //   e8????????           |                     
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_11 = { 68???????? e8???????? 8d4db4 e8???????? 83c418 }
            // n = 5, score = 500
            //   68????????           |                     
            //   e8????????           |                     
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_12 = { 52 6a02 6a00 51 ff75f8 ff15???????? ff75f8 }
            // n = 7, score = 500
            //   52                   | push                edx
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_13 = { 8bce e8???????? e8???????? 83c418 e8???????? e9???????? 52 }
            // n = 7, score = 500
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   e8????????           |                     
            //   e9????????           |                     
            //   52                   | push                edx

        $sequence_14 = { c705????????0c000000 eb31 c705????????0d000000 eb25 83f901 750c }
            // n = 6, score = 500
            //   c705????????0c000000     |     
            //   eb31                 | jmp                 0x33
            //   c705????????0d000000     |     
            //   eb25                 | jmp                 0x27
            //   83f901               | cmp                 ecx, 1
            //   750c                 | jne                 0xe

        $sequence_15 = { 50 68???????? 83ec18 8bcc 68???????? e8???????? }
            // n = 6, score = 500
            //   50                   | push                eax
            //   68????????           |                     
            //   83ec18               | sub                 esp, 0x18
            //   8bcc                 | mov                 ecx, esp
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_16 = { 8bcc 68???????? e8???????? 8d8d78feffff e8???????? 83c418 }
            // n = 6, score = 500
            //   8bcc                 | mov                 ecx, esp
            //   68????????           |                     
            //   e8????????           |                     
            //   8d8d78feffff         | lea                 ecx, [ebp - 0x188]
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_17 = { c78584fdffff0f000000 c68570fdffff00 83fa10 722f 8b8d58fdffff 42 }
            // n = 6, score = 400
            //   c78584fdffff0f000000     | mov    dword ptr [ebp - 0x27c], 0xf
            //   c68570fdffff00       | mov                 byte ptr [ebp - 0x290], 0
            //   83fa10               | cmp                 edx, 0x10
            //   722f                 | jb                  0x31
            //   8b8d58fdffff         | mov                 ecx, dword ptr [ebp - 0x2a8]
            //   42                   | inc                 edx

        $sequence_18 = { c78520fdffff00000000 c78524fdffff0f000000 c68510fdffff00 83fa10 722f }
            // n = 5, score = 400
            //   c78520fdffff00000000     | mov    dword ptr [ebp - 0x2e0], 0
            //   c78524fdffff0f000000     | mov    dword ptr [ebp - 0x2dc], 0xf
            //   c68510fdffff00       | mov                 byte ptr [ebp - 0x2f0], 0
            //   83fa10               | cmp                 edx, 0x10
            //   722f                 | jb                  0x31

        $sequence_19 = { 51 e8???????? 83c408 8b950cfdffff c78520fdffff00000000 c78524fdffff0f000000 }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b950cfdffff         | mov                 edx, dword ptr [ebp - 0x2f4]
            //   c78520fdffff00000000     | mov    dword ptr [ebp - 0x2e0], 0
            //   c78524fdffff0f000000     | mov    dword ptr [ebp - 0x2dc], 0xf

    condition:
        7 of them and filesize < 529408
}