rule win_zxxz_auto {

    meta:
        atk_type = "win.zxxz."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.zxxz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zxxz"
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
        $sequence_0 = { 40 84c9 75ef bf???????? e8???????? 84c0 }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75ef                 | jne                 0xfffffff1
            //   bf????????           |                     
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_1 = { 8b4c244c 64890d00000000 59 5f 5e 5d 8b4c2434 }
            // n = 7, score = 100
            //   8b4c244c             | mov                 ecx, dword ptr [esp + 0x4c]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   8b4c2434             | mov                 ecx, dword ptr [esp + 0x34]

        $sequence_2 = { be04010000 51 89742424 6689842424010000 e8???????? }
            // n = 5, score = 100
            //   be04010000           | mov                 esi, 0x104
            //   51                   | push                ecx
            //   89742424             | mov                 dword ptr [esp + 0x24], esi
            //   6689842424010000     | mov                 word ptr [esp + 0x124], ax
            //   e8????????           |                     

        $sequence_3 = { 84c9 75f9 2bc2 8bd0 33c0 33c9 }
            // n = 6, score = 100
            //   84c9                 | test                cl, cl
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   8bd0                 | mov                 edx, eax
            //   33c0                 | xor                 eax, eax
            //   33c9                 | xor                 ecx, ecx

        $sequence_4 = { c3 81ecc4010000 a1???????? 33c4 898424bc010000 }
            // n = 5, score = 100
            //   c3                   | ret                 
            //   81ecc4010000         | sub                 esp, 0x1c4
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   898424bc010000       | mov                 dword ptr [esp + 0x1bc], eax

        $sequence_5 = { 7424 8b1d???????? 8d54242c 57 }
            // n = 4, score = 100
            //   7424                 | je                  0x26
            //   8b1d????????         |                     
            //   8d54242c             | lea                 edx, [esp + 0x2c]
            //   57                   | push                edi

        $sequence_6 = { ff15???????? 85c0 7539 3805???????? }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7539                 | jne                 0x3b
            //   3805????????         |                     

        $sequence_7 = { 7403 8811 41 40 803800 75f0 }
            // n = 6, score = 100
            //   7403                 | je                  5
            //   8811                 | mov                 byte ptr [ecx], dl
            //   41                   | inc                 ecx
            //   40                   | inc                 eax
            //   803800               | cmp                 byte ptr [eax], 0
            //   75f0                 | jne                 0xfffffff2

        $sequence_8 = { 681c020000 68???????? ffd6 83c40c 68???????? }
            // n = 5, score = 100
            //   681c020000           | push                0x21c
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     

        $sequence_9 = { ff15???????? 8b3d???????? 8bf0 56 6a01 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   6a01                 | push                1

    condition:
        7 of them and filesize < 4142080
}