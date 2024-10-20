rule win_agendacrypt_auto {

    meta:
        atk_type = "win.agendacrypt."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.agendacrypt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agendacrypt"
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
        $sequence_0 = { eb20 8b55ec 8975e8 89f1 57 53 e8???????? }
            // n = 7, score = 100
            //   eb20                 | jmp                 0x22
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   89f1                 | mov                 ecx, esi
            //   57                   | push                edi
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_1 = { 8d55b0 e8???????? eb25 c745b000000000 8d4dd0 8d55b0 e8???????? }
            // n = 7, score = 100
            //   8d55b0               | lea                 edx, [ebp - 0x50]
            //   e8????????           |                     
            //   eb25                 | jmp                 0x27
            //   c745b000000000       | mov                 dword ptr [ebp - 0x50], 0
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   8d55b0               | lea                 edx, [ebp - 0x50]
            //   e8????????           |                     

        $sequence_2 = { c1e204 88443110 89f8 f7d0 c1e004 f30f7e0403 f30f7e4c0308 }
            // n = 7, score = 100
            //   c1e204               | shl                 edx, 4
            //   88443110             | mov                 byte ptr [ecx + esi + 0x10], al
            //   89f8                 | mov                 eax, edi
            //   f7d0                 | not                 eax
            //   c1e004               | shl                 eax, 4
            //   f30f7e0403           | movq                xmm0, qword ptr [ebx + eax]
            //   f30f7e4c0308         | movq                xmm1, qword ptr [ebx + eax + 8]

        $sequence_3 = { c1c71a 31fa 8b7b04 89c3 339d70ffffff 0fcf 21cb }
            // n = 7, score = 100
            //   c1c71a               | rol                 edi, 0x1a
            //   31fa                 | xor                 edx, edi
            //   8b7b04               | mov                 edi, dword ptr [ebx + 4]
            //   89c3                 | mov                 ebx, eax
            //   339d70ffffff         | xor                 ebx, dword ptr [ebp - 0x90]
            //   0fcf                 | bswap               edi
            //   21cb                 | and                 ebx, ecx

        $sequence_4 = { e9???????? 8d543210 8b7508 f20f104a30 f20f114e40 f20f104a28 f20f114e38 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d543210             | lea                 edx, [edx + esi + 0x10]
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   f20f104a30           | movsd               xmm1, qword ptr [edx + 0x30]
            //   f20f114e40           | movsd               qword ptr [esi + 0x40], xmm1
            //   f20f104a28           | movsd               xmm1, qword ptr [edx + 0x28]
            //   f20f114e38           | movsd               qword ptr [esi + 0x38], xmm1

        $sequence_5 = { f20f1101 8b55f0 8d4da8 ff7518 ff7514 ff7510 ff750c }
            // n = 7, score = 100
            //   f20f1101             | movsd               qword ptr [ecx], xmm0
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8d4da8               | lea                 ecx, [ebp - 0x58]
            //   ff7518               | push                dword ptr [ebp + 0x18]
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_6 = { f20f1145c8 0f82de010000 80ff0a 894804 0f85c9000000 8b7d0c 8b55ec }
            // n = 7, score = 100
            //   f20f1145c8           | movsd               qword ptr [ebp - 0x38], xmm0
            //   0f82de010000         | jb                  0x1e4
            //   80ff0a               | cmp                 bh, 0xa
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   0f85c9000000         | jne                 0xcf
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]

        $sequence_7 = { f20f114c2438 f20f108c2488000000 f20f11542430 f20f105028 f20f11442440 f20f115c2418 f20f1018 }
            // n = 7, score = 100
            //   f20f114c2438         | movsd               qword ptr [esp + 0x38], xmm1
            //   f20f108c2488000000     | movsd    xmm1, qword ptr [esp + 0x88]
            //   f20f11542430         | movsd               qword ptr [esp + 0x30], xmm2
            //   f20f105028           | movsd               xmm2, qword ptr [eax + 0x28]
            //   f20f11442440         | movsd               qword ptr [esp + 0x40], xmm0
            //   f20f115c2418         | movsd               qword ptr [esp + 0x18], xmm3
            //   f20f1018             | movsd               xmm3, qword ptr [eax]

        $sequence_8 = { e8???????? e9???????? ffb424fc000000 e8???????? e9???????? e8???????? 89c3 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e9????????           |                     
            //   ffb424fc000000       | push                dword ptr [esp + 0xfc]
            //   e8????????           |                     
            //   e9????????           |                     
            //   e8????????           |                     
            //   89c3                 | mov                 ebx, eax

        $sequence_9 = { ffd1 83c404 8b8c24a0190000 83790400 741f 8b84249c190000 83790809 }
            // n = 7, score = 100
            //   ffd1                 | call                ecx
            //   83c404               | add                 esp, 4
            //   8b8c24a0190000       | mov                 ecx, dword ptr [esp + 0x19a0]
            //   83790400             | cmp                 dword ptr [ecx + 4], 0
            //   741f                 | je                  0x21
            //   8b84249c190000       | mov                 eax, dword ptr [esp + 0x199c]
            //   83790809             | cmp                 dword ptr [ecx + 8], 9

    condition:
        7 of them and filesize < 3340288
}