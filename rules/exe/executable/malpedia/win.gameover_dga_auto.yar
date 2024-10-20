rule win_gameover_dga_auto {

    meta:
        atk_type = "win.gameover_dga."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.gameover_dga."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gameover_dga"
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
        $sequence_0 = { 884617 33c0 40 e9???????? 8a4601 33db 8b6c2434 }
            // n = 7, score = 700
            //   884617               | mov                 byte ptr [esi + 0x17], al
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   e9????????           |                     
            //   8a4601               | mov                 al, byte ptr [esi + 1]
            //   33db                 | xor                 ebx, ebx
            //   8b6c2434             | mov                 ebp, dword ptr [esp + 0x34]

        $sequence_1 = { 397e08 0f84f0000000 8be9 894c2414 8bd1 8b4604 8a0c03 }
            // n = 7, score = 700
            //   397e08               | cmp                 dword ptr [esi + 8], edi
            //   0f84f0000000         | je                  0xf6
            //   8be9                 | mov                 ebp, ecx
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   8bd1                 | mov                 edx, ecx
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   8a0c03               | mov                 cl, byte ptr [ebx + eax]

        $sequence_2 = { 48 7544 397714 763f 8b4710 ff34b0 }
            // n = 6, score = 700
            //   48                   | dec                 eax
            //   7544                 | jne                 0x46
            //   397714               | cmp                 dword ptr [edi + 0x14], esi
            //   763f                 | jbe                 0x41
            //   8b4710               | mov                 eax, dword ptr [edi + 0x10]
            //   ff34b0               | push                dword ptr [eax + esi*4]

        $sequence_3 = { 833d????????00 7566 8d8de8fdffff e8???????? 51 be???????? 56 }
            // n = 7, score = 700
            //   833d????????00       |                     
            //   7566                 | jne                 0x68
            //   8d8de8fdffff         | lea                 ecx, [ebp - 0x218]
            //   e8????????           |                     
            //   51                   | push                ecx
            //   be????????           |                     
            //   56                   | push                esi

        $sequence_4 = { 5f 5b c20c00 8bcf e8???????? 8bf0 }
            // n = 6, score = 700
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   c20c00               | ret                 0xc
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { 56 ff15???????? 85c0 7443 56 be???????? 8d85f8fdffff }
            // n = 7, score = 700
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7443                 | je                  0x45
            //   56                   | push                esi
            //   be????????           |                     
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]

        $sequence_6 = { 8b84245c010000 40 e9???????? 8b476c 33c9 2bc3 }
            // n = 6, score = 700
            //   8b84245c010000       | mov                 eax, dword ptr [esp + 0x15c]
            //   40                   | inc                 eax
            //   e9????????           |                     
            //   8b476c               | mov                 eax, dword ptr [edi + 0x6c]
            //   33c9                 | xor                 ecx, ecx
            //   2bc3                 | sub                 eax, ebx

        $sequence_7 = { ff760c ff7608 6a10 e8???????? 84c0 0f847a010000 8364241c00 }
            // n = 7, score = 700
            //   ff760c               | push                dword ptr [esi + 0xc]
            //   ff7608               | push                dword ptr [esi + 8]
            //   6a10                 | push                0x10
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f847a010000         | je                  0x180
            //   8364241c00           | and                 dword ptr [esp + 0x1c], 0

        $sequence_8 = { e8???????? a1???????? ff7064 ff15???????? 6a53 8d55b8 8bf0 }
            // n = 7, score = 700
            //   e8????????           |                     
            //   a1????????           |                     
            //   ff7064               | push                dword ptr [eax + 0x64]
            //   ff15????????         |                     
            //   6a53                 | push                0x53
            //   8d55b8               | lea                 edx, [ebp - 0x48]
            //   8bf0                 | mov                 esi, eax

        $sequence_9 = { 7510 8b4f10 e8???????? 85c0 75e5 32c0 }
            // n = 6, score = 700
            //   7510                 | jne                 0x12
            //   8b4f10               | mov                 ecx, dword ptr [edi + 0x10]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   75e5                 | jne                 0xffffffe7
            //   32c0                 | xor                 al, al

    condition:
        7 of them and filesize < 540672
}