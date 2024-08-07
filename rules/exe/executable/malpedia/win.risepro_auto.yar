rule win_risepro_auto {

    meta:
        atk_type = "win.risepro."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.risepro."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.risepro"
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
        $sequence_0 = { 0fb645ff 50 8b4de8 e8???????? 8b4dec 83c901 894dec }
            // n = 7, score = 100
            //   0fb645ff             | movzx               eax, byte ptr [ebp - 1]
            //   50                   | push                eax
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   83c901               | or                  ecx, 1
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx

        $sequence_1 = { e8???????? 8945c8 8d4d0c e8???????? 8945cc 8d45d7 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   8d4d0c               | lea                 ecx, [ebp + 0xc]
            //   e8????????           |                     
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8d45d7               | lea                 eax, [ebp - 0x29]
            //   50                   | push                eax

        $sequence_2 = { 8bec 83ec0c 8955f8 894dfc 8b4dfc e8???????? 8bc8 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_3 = { 894214 8b4df8 e8???????? 8945d4 837de010 }
            // n = 5, score = 100
            //   894214               | mov                 dword ptr [edx + 0x14], eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   837de010             | cmp                 dword ptr [ebp - 0x20], 0x10

        $sequence_4 = { 8bcc 8965bc 8d552c 52 e8???????? 8945b8 c645fc04 }
            // n = 7, score = 100
            //   8bcc                 | mov                 ecx, esp
            //   8965bc               | mov                 dword ptr [ebp - 0x44], esp
            //   8d552c               | lea                 edx, [ebp + 0x2c]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8945b8               | mov                 dword ptr [ebp - 0x48], eax
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4

        $sequence_5 = { 33c0 8885eafeffff 33c9 888de9feffff }
            // n = 4, score = 100
            //   33c0                 | xor                 eax, eax
            //   8885eafeffff         | mov                 byte ptr [ebp - 0x116], al
            //   33c9                 | xor                 ecx, ecx
            //   888de9feffff         | mov                 byte ptr [ebp - 0x117], cl

        $sequence_6 = { 6800000080 680000cf00 68???????? 68???????? 6800020000 ff15???????? 89859cfeffff }
            // n = 7, score = 100
            //   6800000080           | push                0x80000000
            //   680000cf00           | push                0xcf0000
            //   68????????           |                     
            //   68????????           |                     
            //   6800020000           | push                0x200
            //   ff15????????         |                     
            //   89859cfeffff         | mov                 dword ptr [ebp - 0x164], eax

        $sequence_7 = { 6886e4fa74 6829895415 e8???????? 8b4dfc 894108 89510c }
            // n = 6, score = 100
            //   6886e4fa74           | push                0x74fae486
            //   6829895415           | push                0x15548929
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   894108               | mov                 dword ptr [ecx + 8], eax
            //   89510c               | mov                 dword ptr [ecx + 0xc], edx

        $sequence_8 = { 33c5 8945ec 56 50 8d45f4 64a300000000 894da8 }
            // n = 7, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   56                   | push                esi
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894da8               | mov                 dword ptr [ebp - 0x58], ecx

        $sequence_9 = { 85ff 780f 3b3d???????? 7307 }
            // n = 4, score = 100
            //   85ff                 | test                edi, edi
            //   780f                 | js                  0x11
            //   3b3d????????         |                     
            //   7307                 | jae                 9

    condition:
        7 of them and filesize < 280576
}