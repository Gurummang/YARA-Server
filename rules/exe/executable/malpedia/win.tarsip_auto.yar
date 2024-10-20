rule win_tarsip_auto {

    meta:
        atk_type = "win.tarsip."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.tarsip."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tarsip"
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
        $sequence_0 = { 8884244f840000 e8???????? 8d94240c840000 52 }
            // n = 4, score = 100
            //   8884244f840000       | mov                 byte ptr [esp + 0x844f], al
            //   e8????????           |                     
            //   8d94240c840000       | lea                 edx, [esp + 0x840c]
            //   52                   | push                edx

        $sequence_1 = { ff15???????? 89ae14420100 8b8610420100 3bc5 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   89ae14420100         | mov                 dword ptr [esi + 0x14214], ebp
            //   8b8610420100         | mov                 eax, dword ptr [esi + 0x14210]
            //   3bc5                 | cmp                 eax, ebp

        $sequence_2 = { ff15???????? 898614420100 85c0 754f }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   898614420100         | mov                 dword ptr [esi + 0x14214], eax
            //   85c0                 | test                eax, eax
            //   754f                 | jne                 0x51

        $sequence_3 = { 80fa2f 7505 b83f000000 8d148500000000 8b442420 c1fa02 c1e106 }
            // n = 7, score = 100
            //   80fa2f               | cmp                 dl, 0x2f
            //   7505                 | jne                 7
            //   b83f000000           | mov                 eax, 0x3f
            //   8d148500000000       | lea                 edx, [eax*4]
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   c1fa02               | sar                 edx, 2
            //   c1e106               | shl                 ecx, 6

        $sequence_4 = { ff15???????? 5b 33c0 5e c3 57 6a00 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   5b                   | pop                 ebx
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   57                   | push                edi
            //   6a00                 | push                0

        $sequence_5 = { 8b08 038ea4830000 8b54240c 8a02 8801 }
            // n = 5, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   038ea4830000         | add                 ecx, dword ptr [esi + 0x83a4]
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8801                 | mov                 byte ptr [ecx], al

        $sequence_6 = { e8???????? 50 e8???????? e8???????? 99 b980841e00 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b980841e00           | mov                 ecx, 0x1e8480

        $sequence_7 = { e8???????? 83c404 c746180f000000 895e14 885e04 8b4c240c 64890d00000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c746180f000000       | mov                 dword ptr [esi + 0x18], 0xf
            //   895e14               | mov                 dword ptr [esi + 0x14], ebx
            //   885e04               | mov                 byte ptr [esi + 4], bl
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_8 = { 8b442418 0374241c 53 8d542418 52 53 53 }
            // n = 7, score = 100
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   0374241c             | add                 esi, dword ptr [esp + 0x1c]
            //   53                   | push                ebx
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_9 = { 83bc240c01000010 7210 8b9424f8000000 52 e8???????? 83c404 c784240c0100000f000000 }
            // n = 7, score = 100
            //   83bc240c01000010     | cmp                 dword ptr [esp + 0x10c], 0x10
            //   7210                 | jb                  0x12
            //   8b9424f8000000       | mov                 edx, dword ptr [esp + 0xf8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c784240c0100000f000000     | mov    dword ptr [esp + 0x10c], 0xf

    condition:
        7 of them and filesize < 360448
}