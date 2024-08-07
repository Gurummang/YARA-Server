rule win_tigerlite_auto {

    meta:
        atk_type = "win.tigerlite."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.tigerlite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tigerlite"
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
        $sequence_0 = { c1f805 83e71f c1e706 8b0485489d4100 83c00c 03c7 50 }
            // n = 7, score = 100
            //   c1f805               | dec                 eax
            //   83e71f               | mov                 eax, dword ptr [eax + 0x18]
            //   c1e706               | dec                 eax
            //   8b0485489d4100       | mov                 edx, dword ptr [eax]
            //   83c00c               | mov                 word ptr [esi + 0xb8], ax
            //   03c7                 | mov                 word ptr [esi + 0x1be], ax
            //   50                   | mov                 dword ptr [esi + 0x68], 0x418778

        $sequence_1 = { 8b85e0f7ffff 85c0 751d 56 ff15???????? b832000000 5f }
            // n = 7, score = 100
            //   8b85e0f7ffff         | je                  0xf
            //   85c0                 | mov                 eax, 0xc8
            //   751d                 | jmp                 0x6e
            //   56                   | dec                 eax
            //   ff15????????         |                     
            //   b832000000           | test                eax, eax
            //   5f                   | je                  0x6b

        $sequence_2 = { 8b8d24e5ffff 50 8b8528e5ffff 8b0485489d4100 }
            // n = 4, score = 100
            //   8b8d24e5ffff         | mov                 edi, 2
            //   50                   | dec                 eax
            //   8b8528e5ffff         | lea                 ecx, [0x1b4d2]
            //   8b0485489d4100       | mov                 word ptr [esp + 0x40], di

        $sequence_3 = { 85c0 740d ff15???????? b8c8000000 eb65 }
            // n = 5, score = 100
            //   85c0                 | lea                 ecx, [ebp + 0x90]
            //   740d                 | mov                 ecx, 0xe5
            //   ff15????????         |                     
            //   b8c8000000           | mov                 ebx, eax
            //   eb65                 | and                 ebx, 3

        $sequence_4 = { ff15???????? cc 4c8d4510 488d15bbc80100 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   cc                   | inc                 edx
            //   4c8d4510             | test                byte ptr [eax + esi + 8], 0x48
            //   488d15bbc80100       | je                  0x40

        $sequence_5 = { 41b8ff030000 c6859000000000 e8???????? 488d1528bc0100 488d8d90000000 e8???????? }
            // n = 6, score = 100
            //   41b8ff030000         | lea                 edx, [0x1c8bb]
            //   c6859000000000       | cmp                 word ptr [ebp - 0x28], dx
            //   e8????????           |                     
            //   488d1528bc0100       | je                  0x44
            //   488d8d90000000       | mov                 word ptr [ebx], si
            //   e8????????           |                     

        $sequence_6 = { 33c0 8bbdbcfdffff 0fbebcc7f8214100 8bc7 89bdbcfdffff 8bbde4fdffff }
            // n = 6, score = 100
            //   33c0                 | and                 dword ptr [esi + 0x3b8], 0
            //   8bbdbcfdffff         | push                0xd
            //   0fbebcc7f8214100     | cmp                 edi, edx
            //   8bc7                 | jne                 0x58
            //   89bdbcfdffff         | mov                 ecx, ebx
            //   8bbde4fdffff         | push                ebx

        $sequence_7 = { 668986b8000000 668986be010000 c7466878874100 83a6b803000000 6a0d e8???????? }
            // n = 6, score = 100
            //   668986b8000000       | mov                 edi, eax
            //   668986be010000       | dec                 eax
            //   c7466878874100       | test                edi, edi
            //   83a6b803000000       | je                  0x411
            //   6a0d                 | dec                 esp
            //   e8????????           |                     

        $sequence_8 = { 4863c2 4803d8 eb61 4b8b84ea604a0200 42f644300848 743e 48ffc3 }
            // n = 7, score = 100
            //   4863c2               | dec                 eax
            //   4803d8               | arpl                dx, ax
            //   eb61                 | dec                 eax
            //   4b8b84ea604a0200     | add                 ebx, eax
            //   42f644300848         | jmp                 0x63
            //   743e                 | dec                 ebx
            //   48ffc3               | mov                 eax, dword ptr [edx + ebp*8 + 0x24a60]

        $sequence_9 = { 663955d8 7442 668933 8a45d8 4b8b8cea604a0200 4288443109 }
            // n = 6, score = 100
            //   663955d8             | dec                 eax
            //   7442                 | inc                 ebx
            //   668933               | int3                
            //   8a45d8               | dec                 esp
            //   4b8b8cea604a0200     | lea                 eax, [ebp + 0x10]
            //   4288443109           | dec                 eax

        $sequence_10 = { 8b3495489d4100 8a441e04 84c0 0f8957020000 }
            // n = 4, score = 100
            //   8b3495489d4100       | and                 edi, 0x1f
            //   8a441e04             | shl                 edi, 6
            //   84c0                 | mov                 eax, dword ptr [eax*4 + 0x419d48]
            //   0f8957020000         | add                 eax, 0xc

        $sequence_11 = { 488bcb 488bf8 e8???????? 4885ff 0f8405040000 4c8d4530 488d0da1a40100 }
            // n = 7, score = 100
            //   488bcb               | inc                 ecx
            //   488bf8               | mov                 eax, 0x3ff
            //   e8????????           |                     
            //   4885ff               | mov                 byte ptr [ebp + 0x90], 0
            //   0f8405040000         | dec                 eax
            //   4c8d4530             | lea                 edx, [0x1bc28]
            //   488d0da1a40100       | dec                 eax

        $sequence_12 = { 488d4c2440 418bd6 e8???????? e9???????? }
            // n = 4, score = 100
            //   488d4c2440           | inc                 edx
            //   418bd6               | mov                 byte ptr [ecx + esi + 9], al
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_13 = { b9e5000000 8bd8 83e303 e8???????? }
            // n = 4, score = 100
            //   b9e5000000           | mov                 al, byte ptr [ebp - 0x28]
            //   8bd8                 | dec                 ebx
            //   83e303               | mov                 ecx, dword ptr [edx + ebp*8 + 0x24a60]
            //   e8????????           |                     

        $sequence_14 = { 3bfa 7556 8bcb e8???????? 53 }
            // n = 5, score = 100
            //   3bfa                 | lea                 eax, [ebp + 0x30]
            //   7556                 | dec                 eax
            //   8bcb                 | lea                 ecx, [0x1a4a1]
            //   e8????????           |                     
            //   53                   | test                eax, eax

        $sequence_15 = { 8d0c00 894dec eb38 8b45f4 8b0485489d4100 }
            // n = 5, score = 100
            //   8d0c00               | mov                 eax, dword ptr [ebp - 0x820]
            //   894dec               | test                eax, eax
            //   eb38                 | jne                 0x21
            //   8b45f4               | push                esi
            //   8b0485489d4100       | mov                 eax, 0x32

    condition:
        7 of them and filesize < 349184
}