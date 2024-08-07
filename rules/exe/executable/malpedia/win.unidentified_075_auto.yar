rule win_unidentified_075_auto {

    meta:
        atk_type = "win.unidentified_075."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-07-11"
        version = "1"
        description = "Detects win.unidentified_075."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_075"
        malpedia_rule_date = "20230705"
        malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
        malpedia_version = "20230715"
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
        $sequence_0 = { e8???????? 83c40c 6808020000 8d95dcf6ffff 52 6a00 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6808020000           | push                0x208
            //   8d95dcf6ffff         | lea                 edx, [ebp - 0x924]
            //   52                   | push                edx
            //   6a00                 | push                0

        $sequence_1 = { 8bc1 5e 5d c3 55 8bec ff15???????? }
            // n = 7, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   ff15????????         |                     

        $sequence_2 = { 52 e8???????? 6a00 8d85ace6ffff 50 8d8dbceeffff 51 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   e8????????           |                     
            //   6a00                 | push                0
            //   8d85ace6ffff         | lea                 eax, [ebp - 0x1954]
            //   50                   | push                eax
            //   8d8dbceeffff         | lea                 ecx, [ebp - 0x1144]
            //   51                   | push                ecx

        $sequence_3 = { 83c40c 33c0 668985d4f4ffff 6806020000 }
            // n = 4, score = 200
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax
            //   668985d4f4ffff       | mov                 word ptr [ebp - 0xb2c], ax
            //   6806020000           | push                0x206

        $sequence_4 = { 837d9400 740d 8b55fc c7821002000000000000 837df000 }
            // n = 5, score = 200
            //   837d9400             | cmp                 dword ptr [ebp - 0x6c], 0
            //   740d                 | je                  0xf
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   c7821002000000000000     | mov    dword ptr [edx + 0x210], 0
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0

        $sequence_5 = { 52 ff15???????? 83c410 b853000000 66898550ffffff }
            // n = 5, score = 200
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10
            //   b853000000           | mov                 eax, 0x53
            //   66898550ffffff       | mov                 word ptr [ebp - 0xb0], ax

        $sequence_6 = { 33c0 668945d0 8d4dd4 51 }
            // n = 4, score = 200
            //   33c0                 | xor                 eax, eax
            //   668945d0             | mov                 word ptr [ebp - 0x30], ax
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   51                   | push                ecx

        $sequence_7 = { 742c 8b4514 85c0 7421 }
            // n = 4, score = 200
            //   742c                 | je                  0x2e
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23

        $sequence_8 = { 85c0 0f8431ffffff b901000000 85c9 0f8515ffffff }
            // n = 5, score = 200
            //   85c0                 | test                eax, eax
            //   0f8431ffffff         | je                  0xffffff37
            //   b901000000           | mov                 ecx, 1
            //   85c9                 | test                ecx, ecx
            //   0f8515ffffff         | jne                 0xffffff1b

        $sequence_9 = { 81eca4000000 894dfc c745f400000000 c745f800000000 }
            // n = 4, score = 200
            //   81eca4000000         | sub                 esp, 0xa4
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0

    condition:
        7 of them and filesize < 393216
}