rule win_boaxxe_auto {

    meta:
        atk_type = "win.boaxxe."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.boaxxe."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.boaxxe"
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
        $sequence_0 = { b904000000 e8???????? 8d55c4 66b8c503 e8???????? 8b55c4 a1???????? }
            // n = 7, score = 100
            //   b904000000           | mov                 ecx, 4
            //   e8????????           |                     
            //   8d55c4               | lea                 edx, [ebp - 0x3c]
            //   66b8c503             | mov                 ax, 0x3c5
            //   e8????????           |                     
            //   8b55c4               | mov                 edx, dword ptr [ebp - 0x3c]
            //   a1????????           |                     

        $sequence_1 = { 0f8c88000000 8d4df4 8b55f8 8b45f8 e8???????? 8b55f4 8d45f8 }
            // n = 7, score = 100
            //   0f8c88000000         | jl                  0x8e
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_2 = { 83c220 8d45f8 e8???????? 8d45f8 e8???????? 8945f4 8b45f4 }
            // n = 7, score = 100
            //   83c220               | add                 edx, 0x20
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   e8????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   e8????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_3 = { 33c0 55 68???????? 64ff30 648920 8bcb b230 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   55                   | push                ebp
            //   68????????           |                     
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   8bcb                 | mov                 ecx, ebx
            //   b230                 | mov                 dl, 0x30

        $sequence_4 = { 85db 7410 8b55f4 8b45ec 8bcb e8???????? }
            // n = 6, score = 100
            //   85db                 | test                ebx, ebx
            //   7410                 | je                  0x12
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_5 = { 8b45cc e8???????? 8bd8 891d???????? 891d???????? 8d45c8 50 }
            // n = 7, score = 100
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   891d????????         |                     
            //   891d????????         |                     
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   50                   | push                eax

        $sequence_6 = { 01d0 c1e003 8b803c58bc6d 8945ec e9???????? 837de808 }
            // n = 6, score = 100
            //   01d0                 | add                 eax, edx
            //   c1e003               | shl                 eax, 3
            //   8b803c58bc6d         | mov                 eax, dword ptr [eax + 0x6dbc583c]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   e9????????           |                     
            //   837de808             | cmp                 dword ptr [ebp - 0x18], 8

        $sequence_7 = { a1???????? e8???????? 8bd0 53 8bc2 e9???????? 33c0 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   53                   | push                ebx
            //   8bc2                 | mov                 eax, edx
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 0342fc 8945ec 8b45f8 8b00 8b5508 0342fc 8945f0 }
            // n = 7, score = 100
            //   0342fc               | add                 eax, dword ptr [edx - 4]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0342fc               | add                 eax, dword ptr [edx - 4]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_9 = { b808000000 e8???????? 8b55f8 58 e8???????? 7504 33db }
            // n = 7, score = 100
            //   b808000000           | mov                 eax, 8
            //   e8????????           |                     
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   58                   | pop                 eax
            //   e8????????           |                     
            //   7504                 | jne                 6
            //   33db                 | xor                 ebx, ebx

    condition:
        7 of them and filesize < 1146880
}