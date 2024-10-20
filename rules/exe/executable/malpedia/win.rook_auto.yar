rule win_rook_auto {

    meta:
        atk_type = "win.rook."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rook"
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
        $sequence_0 = { 488d05478d0200 c7470801000000 48c7471003000000 48894748 488d05c59e0200 }
            // n = 5, score = 100
            //   488d05478d0200       | dec                 esp
            //   c7470801000000       | mov                 eax, ebx
            //   48c7471003000000     | dec                 eax
            //   48894748             | lea                 ecx, [ebp + 0xf0]
            //   488d05c59e0200       | inc                 ecx

        $sequence_1 = { 0f8521ffffff 44882b eb7b 488b9540070000 4c8d05979e0000 498bce }
            // n = 6, score = 100
            //   0f8521ffffff         | mov                 ebx, dword ptr [eax + 0x1c]
            //   44882b               | dec                 eax
            //   eb7b                 | lea                 eax, [eax + 0x20]
            //   488b9540070000       | inc                 ecx
            //   4c8d05979e0000       | movzx               ecx, bl
            //   498bce               | dec                 eax

        $sequence_2 = { 85c0 0f85f5020000 488b8d08080000 488d85f8070000 4c89a424c0080000 488d15ffb90400 }
            // n = 6, score = 100
            //   85c0                 | test                esp, esp
            //   0f85f5020000         | js                  0x1fea
            //   488b8d08080000       | inc                 ecx
            //   488d85f8070000       | mul                 esp
            //   4c89a424c0080000     | mov                 eax, edx
            //   488d15ffb90400       | dec                 eax

        $sequence_3 = { ff15???????? 488bd3 488d0d82ac0400 448bc0 e8???????? 488b0d???????? 4c8bc3 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488bd3               | mov                 dword ptr [esp + 0x10], edi
            //   488d0d82ac0400       | movzx               eax, byte ptr [edx + 1]
            //   448bc0               | dec                 eax
            //   e8????????           |                     
            //   488b0d????????       |                     
            //   4c8bc3               | lea                 edi, [0xfffda7ab]

        $sequence_4 = { 4433d0 418bc1 48c1e808 0fb6c8 41c1e208 420fb6843170990500 4433d0 }
            // n = 7, score = 100
            //   4433d0               | cmp                 dword ptr [ebx + 0x28], esi
            //   418bc1               | dec                 eax
            //   48c1e808             | lea                 ebp, [0x1003b]
            //   0fb6c8               | and                 dword ptr [ebx + 0x50], 0
            //   41c1e208             | and                 dword ptr [ebx + 0x2c], 0
            //   420fb6843170990500     | dec    eax
            //   4433d0               | inc                 dword ptr [ebx + 0x18]

        $sequence_5 = { 488d85f8070000 4c89a424c0080000 488d15ffb90400 4889442428 4c8d25d3450500 4c89ac24b8080000 }
            // n = 6, score = 100
            //   488d85f8070000       | mov                 ecx, esi
            //   4c89a424c0080000     | inc                 eax
            //   488d15ffb90400       | dec                 eax
            //   4889442428           | cwde                
            //   4c8d25d3450500       | xor                 edx, edx
            //   4c89ac24b8080000     | dec                 esp

        $sequence_6 = { 488d542460 488d0d1c380500 e8???????? 488d9510020000 498bcc ff15???????? 4839bd10020000 }
            // n = 7, score = 100
            //   488d542460           | dec                 eax
            //   488d0d1c380500       | lea                 ecx, [0xfffc85f1]
            //   e8????????           |                     
            //   488d9510020000       | dec                 eax
            //   498bcc               | shl                 esi, 2
            //   ff15????????         |                     
            //   4839bd10020000       | movzx               eax, word ptr [ecx + edi*4 + 0x422e0]

        $sequence_7 = { 48894760 488d0535980200 c7475001000000 48c7475804000000 48894778 488d050b710300 c7476801000000 }
            // n = 7, score = 100
            //   48894760             | movapd              xmm2, xmm1
            //   488d0535980200       | movapd              xmm0, xmm1
            //   c7475001000000       | dec                 esp
            //   48c7475804000000     | lea                 ecx, [0xa1f4]
            //   48894778             | subsd               xmm1, xmm2
            //   488d050b710300       | inc                 ecx
            //   c7476801000000       | mulps               xmm1, xmmword ptr [ecx + eax*8]

        $sequence_8 = { 4898 4d8d3446 83ed01 7586 4885f6 0f84d3000000 488bce }
            // n = 7, score = 100
            //   4898                 | dec                 eax
            //   4d8d3446             | mov                 dword ptr [esp + 0x28], ebx
            //   83ed01               | dec                 eax
            //   7586                 | lea                 edx, [0x319a]
            //   4885f6               | jmp                 0x6a
            //   0f84d3000000         | mov                 ecx, 0x208
            //   488bce               | mov                 dword ptr [esp + 0x38], 0x104

        $sequence_9 = { 4c8d05f7140300 488986b0000000 488d8e98000000 e8???????? 8bd8 85c0 0f8517ffffff }
            // n = 7, score = 100
            //   4c8d05f7140300       | lea                 ecx, [0x43145]
            //   488986b0000000       | mov                 dword ptr [esp + 0x30], edi
            //   488d8e98000000       | dec                 eax
            //   e8????????           |                     
            //   8bd8                 | mov                 ecx, eax
            //   85c0                 | dec                 eax
            //   0f8517ffffff         | lea                 edx, [0x43121]

    condition:
        7 of them and filesize < 843776
}