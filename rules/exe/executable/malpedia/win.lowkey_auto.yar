rule win_lowkey_auto {

    meta:
        atk_type = "win.lowkey."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lowkey."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowkey"
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
        $sequence_0 = { 482be0 488b05???????? 4833c4 48898520200000 33d2 c74590636d642e }
            // n = 6, score = 100
            //   482be0               | dec                 eax
            //   488b05????????       |                     
            //   4833c4               | lea                 edx, [ebp + 0x80]
            //   48898520200000       | dec                 eax
            //   33d2                 | mov                 ecx, dword ptr [esp + 0x78]
            //   c74590636d642e       | mov                 dword ptr [esp + 0x60], edi

        $sequence_1 = { 488d3547ed0100 eb16 488b3b 4885ff 740a }
            // n = 5, score = 100
            //   488d3547ed0100       | dec                 eax
            //   eb16                 | xor                 eax, esp
            //   488b3b               | dec                 eax
            //   4885ff               | mov                 dword ptr [ebp + 0x4030], eax
            //   740a                 | xor                 ebx, ebx

        $sequence_2 = { 0f85d7feffff e9???????? b966000000 66894c2435 e9???????? 488d15fa230200 488d8d70010000 }
            // n = 7, score = 100
            //   0f85d7feffff         | lea                 eax, [esp + 0x290]
            //   e9????????           |                     
            //   b966000000           | dec                 eax
            //   66894c2435           | mov                 dword ptr [esp + 0x30], ebx
            //   e9????????           |                     
            //   488d15fa230200       | dec                 eax
            //   488d8d70010000       | mov                 dword ptr [esp + 0x28], eax

        $sequence_3 = { b868000000 6689442435 eb49 488d1517250200 488d8d70010000 ff15???????? 85c0 }
            // n = 7, score = 100
            //   b868000000           | mov                 eax, 0x66
            //   6689442435           | mov                 word ptr [esp + 0x55], ax
            //   eb49                 | dec                 eax
            //   488d1517250200       | lea                 edx, [0x2012a]
            //   488d8d70010000       | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | mov                 ecx, ebx

        $sequence_4 = { 4833c4 4889842490040000 8bfa 488bd9 4885c9 }
            // n = 5, score = 100
            //   4833c4               | mov                 eax, ebx
            //   4889842490040000     | dec                 eax
            //   8bfa                 | lea                 ecx, [0xffff070d]
            //   488bd9               | dec                 eax
            //   4885c9               | shl                 esi, 2

        $sequence_5 = { 85c0 0f84bffeffff b865000000 895c2438 4c8d8570090000 6689442435 488d542430 }
            // n = 7, score = 100
            //   85c0                 | mov                 eax, dword ptr [ecx]
            //   0f84bffeffff         | call                dword ptr [eax + 0x10]
            //   b865000000           | dec                 eax
            //   895c2438             | add                 ecx, 8
            //   4c8d8570090000       | mov                 edx, dword ptr [esp + 0x44]
            //   6689442435           | dec                 eax
            //   488d542430           | test                eax, eax

        $sequence_6 = { ff15???????? e9???????? b9d3000000 663bc1 7551 4c3935???????? 7414 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   e9????????           |                     
            //   b9d3000000           | dec                 eax
            //   663bc1               | lea                 edx, [esp + 0x30]
            //   7551                 | inc                 sp
            //   4c3935????????       |                     
            //   7414                 | mov                 dword ptr [esp + 0x35], esi

        $sequence_7 = { c3 4057 4883ec20 488d3d7b2d0100 48393d???????? 742b }
            // n = 6, score = 100
            //   c3                   | je                  0x32b
            //   4057                 | dec                 eax
            //   4883ec20             | cmp                 ecx, 0x20
            //   488d3d7b2d0100       | jb                  0x307
            //   48393d????????       |                     
            //   742b                 | dec                 eax

        $sequence_8 = { 5e 5b c3 488bcb ff15???????? 4885c0 7504 }
            // n = 7, score = 100
            //   5e                   | lea                 edx, [0x9d68]
            //   5b                   | mov                 eax, 5
            //   c3                   | mov                 dword ptr [ebp + 0x20], eax
            //   488bcb               | mov                 dword ptr [ebp + 0x28], eax
            //   ff15????????         |                     
            //   4885c0               | dec                 eax
            //   7504                 | lea                 eax, [ebp - 0x18]

        $sequence_9 = { eb87 4055 53 57 488dac2470dfffff b890210000 }
            // n = 6, score = 100
            //   eb87                 | dec                 eax
            //   4055                 | mov                 ecx, eax
            //   53                   | dec                 eax
            //   57                   | lea                 edx, [0x1fdcc]
            //   488dac2470dfffff     | dec                 eax
            //   b890210000           | test                eax, eax

    condition:
        7 of them and filesize < 643072
}