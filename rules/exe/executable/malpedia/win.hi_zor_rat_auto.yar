rule win_hi_zor_rat_auto {

    meta:
        atk_type = "win.hi_zor_rat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hi_zor_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hi_zor_rat"
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
        $sequence_0 = { c644303080 8b4e24 83e13f 80f937 7614 8bc6 e8???????? }
            // n = 7, score = 200
            //   c644303080           | mov                 byte ptr [eax + esi + 0x30], 0x80
            //   8b4e24               | mov                 ecx, dword ptr [esi + 0x24]
            //   83e13f               | and                 ecx, 0x3f
            //   80f937               | cmp                 cl, 0x37
            //   7614                 | jbe                 0x16
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     

        $sequence_1 = { ff15???????? 8b4d08 57 8bf0 51 56 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   8bf0                 | mov                 esi, eax
            //   51                   | push                ecx
            //   56                   | push                esi

        $sequence_2 = { e8???????? 8b1d???????? 83c418 6804010000 8d8df4fdffff 51 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b1d????????         |                     
            //   83c418               | add                 esp, 0x18
            //   6804010000           | push                0x104
            //   8d8df4fdffff         | lea                 ecx, [ebp - 0x20c]
            //   51                   | push                ecx

        $sequence_3 = { 23da 8bfa 8b5014 f7d7 }
            // n = 4, score = 200
            //   23da                 | and                 ebx, edx
            //   8bfa                 | mov                 edi, edx
            //   8b5014               | mov                 edx, dword ptr [eax + 0x14]
            //   f7d7                 | not                 edi

        $sequence_4 = { 8b5818 8db41e604b0000 c1e610 c1ef10 0bfe }
            // n = 5, score = 200
            //   8b5818               | mov                 ebx, dword ptr [eax + 0x18]
            //   8db41e604b0000       | lea                 esi, [esi + ebx + 0x4b60]
            //   c1e610               | shl                 esi, 0x10
            //   c1ef10               | shr                 edi, 0x10
            //   0bfe                 | or                  edi, esi

        $sequence_5 = { 037018 f7d2 8975f8 897014 8bfa 0b55f8 }
            // n = 6, score = 200
            //   037018               | add                 esi, dword ptr [eax + 0x18]
            //   f7d2                 | not                 edx
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   897014               | mov                 dword ptr [eax + 0x14], esi
            //   8bfa                 | mov                 edi, edx
            //   0b55f8               | or                  edx, dword ptr [ebp - 8]

        $sequence_6 = { 57 51 50 8945f4 e8???????? 8b450c }
            // n = 6, score = 200
            //   57                   | push                edi
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_7 = { 50 51 e8???????? 83c424 893e 5f 5e }
            // n = 7, score = 200
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   893e                 | mov                 dword ptr [esi], edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { ffd6 8b55ec 83c404 52 ffd6 83c404 }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   83c404               | add                 esp, 4
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   83c404               | add                 esp, 4

        $sequence_9 = { 83c40c 6a00 8d450c 50 6800e00100 8d4608 50 }
            // n = 7, score = 200
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   8d450c               | lea                 eax, [ebp + 0xc]
            //   50                   | push                eax
            //   6800e00100           | push                0x1e000
            //   8d4608               | lea                 eax, [esi + 8]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 73728
}