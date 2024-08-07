rule win_roopirs_auto {

    meta:
        atk_type = "win.roopirs."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.roopirs."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roopirs"
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
        $sequence_0 = { c745fc47000000 8b4dd8 51 68???????? ff15???????? 8945c0 }
            // n = 6, score = 100
            //   c745fc47000000       | mov                 dword ptr [ebp - 4], 0x47
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   51                   | push                ecx
            //   68????????           |                     
            //   ff15????????         |                     
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax

        $sequence_1 = { 50 ff15???????? 898530ffffff eb0a c78530ffffff00000000 33c9 837da800 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   898530ffffff         | mov                 dword ptr [ebp - 0xd0], eax
            //   eb0a                 | jmp                 0xc
            //   c78530ffffff00000000     | mov    dword ptr [ebp - 0xd0], 0
            //   33c9                 | xor                 ecx, ecx
            //   837da800             | cmp                 dword ptr [ebp - 0x58], 0

        $sequence_2 = { ff15???????? 8d4db0 ff15???????? c745fc07000000 833d????????00 751c 68???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8d4db0               | lea                 ecx, [ebp - 0x50]
            //   ff15????????         |                     
            //   c745fc07000000       | mov                 dword ptr [ebp - 4], 7
            //   833d????????00       |                     
            //   751c                 | jne                 0x1e
            //   68????????           |                     

        $sequence_3 = { 8945b0 837db000 7d1d 6a20 68???????? 8b45dc 50 }
            // n = 7, score = 100
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   837db000             | cmp                 dword ptr [ebp - 0x50], 0
            //   7d1d                 | jge                 0x1f
            //   6a20                 | push                0x20
            //   68????????           |                     
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax

        $sequence_4 = { 8d55d4 52 6a05 ff15???????? 83c418 8d45bc 50 }
            // n = 7, score = 100
            //   8d55d4               | lea                 edx, [ebp - 0x2c]
            //   52                   | push                edx
            //   6a05                 | push                5
            //   ff15????????         |                     
            //   83c418               | add                 esp, 0x18
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   50                   | push                eax

        $sequence_5 = { 8b02 8b4d80 51 ff5014 dbe2 89857cffffff }
            // n = 6, score = 100
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8b4d80               | mov                 ecx, dword ptr [ebp - 0x80]
            //   51                   | push                ecx
            //   ff5014               | call                dword ptr [eax + 0x14]
            //   dbe2                 | fnclex              
            //   89857cffffff         | mov                 dword ptr [ebp - 0x84], eax

        $sequence_6 = { 8b4508 50 8b08 ff5104 8b5514 56 8d45bc }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5104               | call                dword ptr [ecx + 4]
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   56                   | push                esi
            //   8d45bc               | lea                 eax, [ebp - 0x44]

        $sequence_7 = { c78544ffffff00000000 8b45ac 89458c 8d4dcc 51 8b558c }
            // n = 6, score = 100
            //   c78544ffffff00000000     | mov    dword ptr [ebp - 0xbc], 0
            //   8b45ac               | mov                 eax, dword ptr [ebp - 0x54]
            //   89458c               | mov                 dword ptr [ebp - 0x74], eax
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   51                   | push                ecx
            //   8b558c               | mov                 edx, dword ptr [ebp - 0x74]

        $sequence_8 = { 68???????? 68???????? ff15???????? c78548ffffffd4624000 eb0a }
            // n = 5, score = 100
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   c78548ffffffd4624000     | mov    dword ptr [ebp - 0xb8], 0x4062d4
            //   eb0a                 | jmp                 0xc

        $sequence_9 = { 8d4dc8 ff15???????? c745fc07000000 8b4dd8 51 68???????? }
            // n = 6, score = 100
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   ff15????????         |                     
            //   c745fc07000000       | mov                 dword ptr [ebp - 4], 7
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   51                   | push                ecx
            //   68????????           |                     

    condition:
        7 of them and filesize < 344064
}