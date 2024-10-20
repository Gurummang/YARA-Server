rule win_cryptolocker_auto {

    meta:
        atk_type = "win.cryptolocker."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.cryptolocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptolocker"
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
        $sequence_0 = { 8d4a9f 6683f905 770f c1e004 }
            // n = 4, score = 600
            //   8d4a9f               | lea                 ecx, [edx - 0x61]
            //   6683f905             | cmp                 cx, 5
            //   770f                 | ja                  0x11
            //   c1e004               | shl                 eax, 4

        $sequence_1 = { 0f858f000000 a1???????? 85c0 7509 }
            // n = 4, score = 600
            //   0f858f000000         | jne                 0x95
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7509                 | jne                 0xb

        $sequence_2 = { 898431ecfeffff 8b4ee8 85c9 740e 8b01 }
            // n = 5, score = 600
            //   898431ecfeffff       | mov                 dword ptr [ecx + esi - 0x114], eax
            //   8b4ee8               | mov                 ecx, dword ptr [esi - 0x18]
            //   85c9                 | test                ecx, ecx
            //   740e                 | je                  0x10
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_3 = { ff7720 56 ff15???????? 8b4510 8b4b04 5f 5e }
            // n = 7, score = 600
            //   ff7720               | push                dword ptr [edi + 0x20]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { 7405 83f802 7549 85c9 }
            // n = 4, score = 600
            //   7405                 | je                  7
            //   83f802               | cmp                 eax, 2
            //   7549                 | jne                 0x4b
            //   85c9                 | test                ecx, ecx

        $sequence_5 = { 8b75fc 33c9 85c0 0f48f1 7522 85f6 781e }
            // n = 7, score = 600
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax
            //   0f48f1               | cmovs               esi, ecx
            //   7522                 | jne                 0x24
            //   85f6                 | test                esi, esi
            //   781e                 | js                  0x20

        $sequence_6 = { c20800 55 8bec 83ec08 53 56 8b7508 }
            // n = 7, score = 600
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec08               | sub                 esp, 8
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_7 = { 8b4ee8 85c9 740e 8b01 6a01 8b4004 03c8 }
            // n = 7, score = 600
            //   8b4ee8               | mov                 ecx, dword ptr [esi - 0x18]
            //   85c9                 | test                ecx, ecx
            //   740e                 | je                  0x10
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   6a01                 | push                1
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   03c8                 | add                 ecx, eax

        $sequence_8 = { 55 8bec 56 8b750c 8d8600ffffff 83f801 7723 }
            // n = 7, score = 600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8d8600ffffff         | lea                 eax, [esi - 0x100]
            //   83f801               | cmp                 eax, 1
            //   7723                 | ja                  0x25

        $sequence_9 = { 0fb7044a 83f820 740f 83f809 7205 83f80d }
            // n = 6, score = 600
            //   0fb7044a             | movzx               eax, word ptr [edx + ecx*2]
            //   83f820               | cmp                 eax, 0x20
            //   740f                 | je                  0x11
            //   83f809               | cmp                 eax, 9
            //   7205                 | jb                  7
            //   83f80d               | cmp                 eax, 0xd

    condition:
        7 of them and filesize < 778240
}