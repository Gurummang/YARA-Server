rule win_rgdoor_auto {

    meta:
        atk_type = "win.rgdoor."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rgdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rgdoor"
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
        $sequence_0 = { 7512 448bfb 448be3 4c8d35d4870100 e9???????? bd01000000 ba98000000 }
            // n = 7, score = 100
            //   7512                 | mov                 byte ptr [ebp - 0x3b], cl
            //   448bfb               | inc                 ecx
            //   448be3               | movzx               ecx, bh
            //   4c8d35d4870100       | and                 cl, 0xf
            //   e9????????           |                     
            //   bd01000000           | shl                 cl, 2
            //   ba98000000           | inc                 ecx

        $sequence_1 = { 488bce eb9d 33db 41b803010000 488bd6 e8???????? }
            // n = 6, score = 100
            //   488bce               | jmp                 0x338
            //   eb9d                 | dec                 eax
            //   33db                 | mov                 ecx, edi
            //   41b803010000         | dec                 eax
            //   488bd6               | mov                 eax, edi
            //   e8????????           |                     

        $sequence_2 = { 4533f6 eb0e 4983ceff 90 49ffc6 42381c32 75f7 }
            // n = 7, score = 100
            //   4533f6               | lea                 ecx, [ebp - 0x10]
            //   eb0e                 | dec                 eax
            //   4983ceff             | mov                 ecx, eax
            //   90                   | dec                 eax
            //   49ffc6               | lea                 edx, [ebp - 0x68]
            //   42381c32             | dec                 eax
            //   75f7                 | lea                 edx, [0x158a1]

        $sequence_3 = { e8???????? b802000000 eb30 48837dd010 720a 488b4db8 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   b802000000           | jne                 0x29a
            //   eb30                 | dec                 ebp
            //   48837dd010           | cmp                 byte ptr [eax + edi - 2], 0x3d
            //   720a                 | dec                 eax
            //   488b4db8             | mov                 dword ptr [eax - 0xd8], esi

        $sequence_4 = { e8???????? 488d05554b0200 4889442458 488d15398d0200 488d4c2458 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   488d05554b0200       | dec                 eax
            //   4889442458           | arpl                word ptr [eax + 4], cx
            //   488d15398d0200       | lea                 edx, [ecx - 0x10]
            //   488d4c2458           | dec                 eax

        $sequence_5 = { e8???????? 83f8ff 0f8490050000 80bc247001000077 750a 8bde 448be6 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83f8ff               | dec                 eax
            //   0f8490050000         | mov                 eax, dword ptr [ecx - 0x10]
            //   80bc247001000077     | inc                 esp
            //   750a                 | lea                 eax, [ebp + 2]
            //   8bde                 | dec                 eax
            //   448be6               | lea                 edx, [0x298cf]

        $sequence_6 = { 8938 e8???????? 488d1d8b390200 4885c0 7404 }
            // n = 5, score = 100
            //   8938                 | dec                 esp
            //   e8????????           |                     
            //   488d1d8b390200       | lea                 esp, [0x22f84]
            //   4885c0               | and                 eax, 0x1f
            //   7404                 | dec                 eax

        $sequence_7 = { 4883ec20 488d3d8bf90100 48393d???????? 742b }
            // n = 4, score = 100
            //   4883ec20             | dec                 eax
            //   488d3d8bf90100       | mov                 edx, eax
            //   48393d????????       |                     
            //   742b                 | nop                 dword ptr [eax + eax]

        $sequence_8 = { 48837db010 480f435598 41b822000000 488d8de8000000 e8???????? 4885c0 488b85e0000000 }
            // n = 7, score = 100
            //   48837db010           | dec                 eax
            //   480f435598           | mov                 ecx, ebx
            //   41b822000000         | dec                 eax
            //   488d8de8000000       | arpl                word ptr [eax + 4], dx
            //   e8????????           |                     
            //   4885c0               | dec                 eax
            //   488b85e0000000       | lea                 eax, [0x288bc]

        $sequence_9 = { 488bce ff15???????? 8bf8 eb25 488b8c2490000000 e9???????? 48895c2420 }
            // n = 7, score = 100
            //   488bce               | dec                 eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 dword ptr [ecx], eax
            //   eb25                 | push                edi
            //   488b8c2490000000     | dec                 eax
            //   e9????????           |                     
            //   48895c2420           | sub                 esp, 0x20

    condition:
        7 of them and filesize < 475136
}