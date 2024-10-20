rule win_whispergate_auto {

    meta:
        atk_type = "win.whispergate."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.whispergate."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.whispergate"
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
        $sequence_0 = { 89d0 80f92f 0f846b060000 80f95c 0f8462060000 8d50ff }
            // n = 6, score = 300
            //   89d0                 | mov                 eax, edx
            //   80f92f               | cmp                 cl, 0x2f
            //   0f846b060000         | je                  0x671
            //   80f95c               | cmp                 cl, 0x5c
            //   0f8462060000         | je                  0x668
            //   8d50ff               | lea                 edx, [eax - 1]

        $sequence_1 = { 0f8409010000 83fb2f 0f8400010000 83fb5c }
            // n = 4, score = 300
            //   0f8409010000         | je                  0x10f
            //   83fb2f               | cmp                 ebx, 0x2f
            //   0f8400010000         | je                  0x106
            //   83fb5c               | cmp                 ebx, 0x5c

        $sequence_2 = { f6044840 0f8448ffffff 397dcc 7275 8b45d0 85c0 756e }
            // n = 7, score = 300
            //   f6044840             | test                byte ptr [eax + ecx*2], 0x40
            //   0f8448ffffff         | je                  0xffffff4e
            //   397dcc               | cmp                 dword ptr [ebp - 0x34], edi
            //   7275                 | jb                  0x77
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   85c0                 | test                eax, eax
            //   756e                 | jne                 0x70

        $sequence_3 = { 53 31c0 0fa2 85c0 0f84db000000 }
            // n = 5, score = 300
            //   53                   | push                ebx
            //   31c0                 | xor                 eax, eax
            //   0fa2                 | cpuid               
            //   85c0                 | test                eax, eax
            //   0f84db000000         | je                  0xe1

        $sequence_4 = { 85ed 75d3 8b542420 8b742424 }
            // n = 4, score = 300
            //   85ed                 | test                ebp, ebp
            //   75d3                 | jne                 0xffffffd5
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   8b742424             | mov                 esi, dword ptr [esp + 0x24]

        $sequence_5 = { 55 57 56 53 81ec2c010000 8b842440010000 85c0 }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   57                   | push                edi
            //   56                   | push                esi
            //   53                   | push                ebx
            //   81ec2c010000         | sub                 esp, 0x12c
            //   8b842440010000       | mov                 eax, dword ptr [esp + 0x140]
            //   85c0                 | test                eax, eax

        $sequence_6 = { 75e8 890424 e8???????? 89c7 8b44241c }
            // n = 5, score = 300
            //   75e8                 | jne                 0xffffffea
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   89c7                 | mov                 edi, eax
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]

        $sequence_7 = { 56 53 83ec10 8b742420 813e???????? 740e }
            // n = 6, score = 300
            //   56                   | push                esi
            //   53                   | push                ebx
            //   83ec10               | sub                 esp, 0x10
            //   8b742420             | mov                 esi, dword ptr [esp + 0x20]
            //   813e????????         |                     
            //   740e                 | je                  0x10

        $sequence_8 = { e9???????? 837dd427 0f84e4000000 83c001 }
            // n = 4, score = 300
            //   e9????????           |                     
            //   837dd427             | cmp                 dword ptr [ebp - 0x2c], 0x27
            //   0f84e4000000         | je                  0xea
            //   83c001               | add                 eax, 1

        $sequence_9 = { 83c001 85c9 751e 83fa2a 7444 83fa3f 743f }
            // n = 7, score = 300
            //   83c001               | add                 eax, 1
            //   85c9                 | test                ecx, ecx
            //   751e                 | jne                 0x20
            //   83fa2a               | cmp                 edx, 0x2a
            //   7444                 | je                  0x46
            //   83fa3f               | cmp                 edx, 0x3f
            //   743f                 | je                  0x41

    condition:
        7 of them and filesize < 114688
}