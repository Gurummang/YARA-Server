rule win_cheesetray_auto {

    meta:
        atk_type = "win.cheesetray."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.cheesetray."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cheesetray"
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
        $sequence_0 = { 66898424c4000000 e8???????? 8b4d08 83c40c 51 8d54240c 33c0 }
            // n = 7, score = 200
            //   66898424c4000000     | mov                 word ptr [esp + 0xc4], ax
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   83c40c               | add                 esp, 0xc
            //   51                   | push                ecx
            //   8d54240c             | lea                 edx, [esp + 0xc]
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { c20c00 397368 740e 56 e8???????? 83c404 83f8ff }
            // n = 7, score = 200
            //   c20c00               | ret                 0xc
            //   397368               | cmp                 dword ptr [ebx + 0x68], esi
            //   740e                 | je                  0x10
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83f8ff               | cmp                 eax, -1

        $sequence_2 = { 03cf 8988bc160000 8b3cb5f0234400 8b5d08 85ff 0f8487fdffff 2b14b5282d4400 }
            // n = 7, score = 200
            //   03cf                 | add                 ecx, edi
            //   8988bc160000         | mov                 dword ptr [eax + 0x16bc], ecx
            //   8b3cb5f0234400       | mov                 edi, dword ptr [esi*4 + 0x4423f0]
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   85ff                 | test                edi, edi
            //   0f8487fdffff         | je                  0xfffffd8d
            //   2b14b5282d4400       | sub                 edx, dword ptr [esi*4 + 0x442d28]

        $sequence_3 = { 8bf8 85ff 745d 0fb755f0 8b45ec 52 50 }
            // n = 7, score = 200
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   745d                 | je                  0x5f
            //   0fb755f0             | movzx               edx, word ptr [ebp - 0x10]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_4 = { e8???????? 8b442434 3bc7 7403 50 ffd6 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   3bc7                 | cmp                 eax, edi
            //   7403                 | je                  5
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_5 = { 8d0c00 8d442428 50 52 e8???????? 83c408 894608 }
            // n = 7, score = 200
            //   8d0c00               | lea                 ecx, [eax + eax]
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   894608               | mov                 dword ptr [esi + 8], eax

        $sequence_6 = { 8bda c1eb18 33049da02d4400 81e2ff000000 330495a0394400 83c120 3341f8 }
            // n = 7, score = 200
            //   8bda                 | mov                 ebx, edx
            //   c1eb18               | shr                 ebx, 0x18
            //   33049da02d4400       | xor                 eax, dword ptr [ebx*4 + 0x442da0]
            //   81e2ff000000         | and                 edx, 0xff
            //   330495a0394400       | xor                 eax, dword ptr [edx*4 + 0x4439a0]
            //   83c120               | add                 ecx, 0x20
            //   3341f8               | xor                 eax, dword ptr [ecx - 8]

        $sequence_7 = { 8b4dfc 5f 5e a3???????? 890d???????? b801000000 5b }
            // n = 7, score = 200
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   a3????????           |                     
            //   890d????????         |                     
            //   b801000000           | mov                 eax, 1
            //   5b                   | pop                 ebx

        $sequence_8 = { e8???????? 8b45f8 83c40c 53 53 8d4dec 51 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c40c               | add                 esp, 0xc
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   51                   | push                ecx

        $sequence_9 = { 83c410 33c0 5f 66398500ffffff 740c 40 6683bc4500ffffff00 }
            // n = 7, score = 200
            //   83c410               | add                 esp, 0x10
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   66398500ffffff       | cmp                 word ptr [ebp - 0x100], ax
            //   740c                 | je                  0xe
            //   40                   | inc                 eax
            //   6683bc4500ffffff00     | cmp    word ptr [ebp + eax*2 - 0x100], 0

    condition:
        7 of them and filesize < 8626176
}