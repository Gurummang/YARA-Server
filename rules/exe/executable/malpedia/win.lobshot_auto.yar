rule win_lobshot_auto {

    meta:
        atk_type = "win.lobshot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lobshot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lobshot"
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
        $sequence_0 = { 895c2414 85f6 7410 6a02 56 ff15???????? 56 }
            // n = 7, score = 200
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   85f6                 | test                esi, esi
            //   7410                 | je                  0x12
            //   6a02                 | push                2
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_1 = { 8b4508 8bd1 85c0 7409 c60200 42 }
            // n = 6, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bd1                 | mov                 edx, ecx
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   c60200               | mov                 byte ptr [edx], 0
            //   42                   | inc                 edx

        $sequence_2 = { 728d ff742418 ff15???????? 8b74241c 43 83fb04 0f8e42ffffff }
            // n = 7, score = 200
            //   728d                 | jb                  0xffffff8f
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   ff15????????         |                     
            //   8b74241c             | mov                 esi, dword ptr [esp + 0x1c]
            //   43                   | inc                 ebx
            //   83fb04               | cmp                 ebx, 4
            //   0f8e42ffffff         | jle                 0xffffff48

        $sequence_3 = { 85d2 7905 895e18 8bd3 57 6a2a }
            // n = 6, score = 200
            //   85d2                 | test                edx, edx
            //   7905                 | jns                 7
            //   895e18               | mov                 dword ptr [esi + 0x18], ebx
            //   8bd3                 | mov                 edx, ebx
            //   57                   | push                edi
            //   6a2a                 | push                0x2a

        $sequence_4 = { 0f8485000000 8b461c 85c0 747e 8b7804 83ff2a 740d }
            // n = 7, score = 200
            //   0f8485000000         | je                  0x8b
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   85c0                 | test                eax, eax
            //   747e                 | je                  0x80
            //   8b7804               | mov                 edi, dword ptr [eax + 4]
            //   83ff2a               | cmp                 edi, 0x2a
            //   740d                 | je                  0xf

        $sequence_5 = { 0f42c8 33ff 894d08 47 8b4e6c 3bcf 771f }
            // n = 7, score = 200
            //   0f42c8               | cmovb               ecx, eax
            //   33ff                 | xor                 edi, edi
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   47                   | inc                 edi
            //   8b4e6c               | mov                 ecx, dword ptr [esi + 0x6c]
            //   3bcf                 | cmp                 ecx, edi
            //   771f                 | ja                  0x21

        $sequence_6 = { 8b55f8 33ff 85d2 7839 8b5dfc 0fb774bb02 85f6 }
            // n = 7, score = 200
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   33ff                 | xor                 edi, edi
            //   85d2                 | test                edx, edx
            //   7839                 | js                  0x3b
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   0fb774bb02           | movzx               esi, word ptr [ebx + edi*4 + 2]
            //   85f6                 | test                esi, esi

        $sequence_7 = { 8b4e08 8a86b1160000 88040a ff4614 0fb786b4160000 8386b4160000f3 }
            // n = 6, score = 200
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8a86b1160000         | mov                 al, byte ptr [esi + 0x16b1]
            //   88040a               | mov                 byte ptr [edx + ecx], al
            //   ff4614               | inc                 dword ptr [esi + 0x14]
            //   0fb786b4160000       | movzx               eax, word ptr [esi + 0x16b4]
            //   8386b4160000f3       | add                 dword ptr [esi + 0x16b4], -0xd

        $sequence_8 = { 53 ff15???????? 8b0d???????? 8b15???????? 2b15???????? 8d4102 83e902 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   8b15????????         |                     
            //   2b15????????         |                     
            //   8d4102               | lea                 eax, [ecx + 2]
            //   83e902               | sub                 ecx, 2

        $sequence_9 = { 895004 8b8348140000 99 2bc2 8bf0 d1fe }
            // n = 6, score = 200
            //   895004               | mov                 dword ptr [eax + 4], edx
            //   8b8348140000         | mov                 eax, dword ptr [ebx + 0x1448]
            //   99                   | cdq                 
            //   2bc2                 | sub                 eax, edx
            //   8bf0                 | mov                 esi, eax
            //   d1fe                 | sar                 esi, 1

    condition:
        7 of them and filesize < 247808
}