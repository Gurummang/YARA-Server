rule win_azov_wiper_auto {

    meta:
        atk_type = "win.azov_wiper."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.azov_wiper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.azov_wiper"
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
        $sequence_0 = { 4c8bc8 4885c0 7455 488d442440 }
            // n = 4, score = 100
            //   4c8bc8               | dec                 eax
            //   4885c0               | mov                 ebx, ecx
            //   7455                 | xor                 esi, esi
            //   488d442440           | mov                 ebp, 1

        $sequence_1 = { 488d5201 6685c0 75ee 488b05???????? 488bcb 488b10 ff9250010000 }
            // n = 7, score = 100
            //   488d5201             | call                dword ptr [eax + 0x10]
            //   6685c0               | xor                 edx, edx
            //   75ee                 | inc                 ecx
            //   488b05????????       |                     
            //   488bcb               | mov                 eax, 0x8000
            //   488b10               | dec                 eax
            //   ff9250010000         | mov                 eax, dword ptr [ecx + 8]

        $sequence_2 = { 41ff9288010000 85c0 740f 4881c79a020000 4889bc2410030000 483bbc2418030000 0f8c73ffffff }
            // n = 7, score = 100
            //   41ff9288010000       | inc                 ebp
            //   85c0                 | xor                 eax, eax
            //   740f                 | mov                 edx, 0x29a
            //   4881c79a020000       | dec                 eax
            //   4889bc2410030000     | mov                 ecx, ebx
            //   483bbc2418030000     | dec                 esp
            //   0f8c73ffffff         | mov                 edx, dword ptr [eax]

        $sequence_3 = { 48894c2440 4533c0 48898c2470080000 4c8b10 488d842470080000 }
            // n = 5, score = 100
            //   48894c2440           | nop                 word ptr [eax + eax]
            //   4533c0               | test                edi, edi
            //   48898c2470080000     | je                  0x2d4
            //   4c8b10               | dec                 eax
            //   488d842470080000     | mov                 eax, dword ptr [edx]

        $sequence_4 = { 33d2 33c9 48897c2420 4c8b10 41ff92b0000000 8bce }
            // n = 6, score = 100
            //   33d2                 | inc                 ebp
            //   33c9                 | xor                 eax, eax
            //   48897c2420           | mov                 edx, 0x29a
            //   4c8b10               | dec                 eax
            //   41ff92b0000000       | mov                 ecx, ebx
            //   8bce                 | dec                 esp

        $sequence_5 = { 4c8b00 41ff5058 85c0 0f84c6000000 4c89b42480000000 448d4b04 }
            // n = 6, score = 100
            //   4c8b00               | xor                 ecx, ecx
            //   41ff5058             | jne                 0x72
            //   85c0                 | dec                 eax
            //   0f84c6000000         | mov                 ecx, ebx
            //   4c89b42480000000     | dec                 eax
            //   448d4b04             | mov                 edx, ebx

        $sequence_6 = { 488bcb 4c8b10 41ff9288010000 85c0 740f 4881c79a020000 }
            // n = 6, score = 100
            //   488bcb               | mov                 dword ptr [esp + 0x30], ecx
            //   4c8b10               | dec                 eax
            //   41ff9288010000       | mov                 dword ptr [esp + 0x28], 0xf003f
            //   85c0                 | dec                 esp
            //   740f                 | mov                 edx, dword ptr [eax]
            //   4881c79a020000       | dec                 eax

        $sequence_7 = { 4883ec20 4080e4f0 c645f356 c645f469 c645f572 }
            // n = 5, score = 100
            //   4883ec20             | je                  0x75
            //   4080e4f0             | dec                 eax
            //   c645f356             | mov                 ecx, ebx
            //   c645f469             | dec                 eax
            //   c645f572             | mov                 dword ptr [esp + 0xb0], edi

        $sequence_8 = { 488945f8 4883ec08 48890424 4883ec08 }
            // n = 4, score = 100
            //   488945f8             | mov                 edx, edi
            //   4883ec08             | dec                 eax
            //   48890424             | mov                 ecx, esi
            //   4883ec08             | dec                 eax

        $sequence_9 = { 0f8493000000 488bd0 488bcb 482bd3 }
            // n = 4, score = 100
            //   0f8493000000         | lea                 ecx, [esp + 0x30]
            //   488bd0               | movsd               qword ptr [esp + 0x260], xmm6
            //   488bcb               | jb                  0xfffffefb
            //   482bd3               | dec                 eax

    condition:
        7 of them and filesize < 73728
}