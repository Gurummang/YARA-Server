rule win_xiaoba_auto {

    meta:
        atk_type = "win.xiaoba."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xiaoba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xiaoba"
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
        $sequence_0 = { 58 8945ec e9???????? 8b5dfc 83c320 895dd0 6801030080 }
            // n = 7, score = 100
            //   58                   | pop                 eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   e9????????           |                     
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   83c320               | add                 ebx, 0x20
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   6801030080           | push                0x80000301

        $sequence_1 = { b801000000 c20c00 8b9024010000 8b44240c 8910 b801000000 c20c00 }
            // n = 7, score = 100
            //   b801000000           | mov                 eax, 1
            //   c20c00               | ret                 0xc
            //   8b9024010000         | mov                 edx, dword ptr [eax + 0x124]
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8910                 | mov                 dword ptr [eax], edx
            //   b801000000           | mov                 eax, 1
            //   c20c00               | ret                 0xc

        $sequence_2 = { 8b5c243c 8b7c2464 8b542428 8b442430 03c3 42 89442430 }
            // n = 7, score = 100
            //   8b5c243c             | mov                 ebx, dword ptr [esp + 0x3c]
            //   8b7c2464             | mov                 edi, dword ptr [esp + 0x64]
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   8b442430             | mov                 eax, dword ptr [esp + 0x30]
            //   03c3                 | add                 eax, ebx
            //   42                   | inc                 edx
            //   89442430             | mov                 dword ptr [esp + 0x30], eax

        $sequence_3 = { dc442410 dd5c2410 e9???????? db8740010000 dc6c2418 dd5c2418 e9???????? }
            // n = 7, score = 100
            //   dc442410             | fadd                qword ptr [esp + 0x10]
            //   dd5c2410             | fstp                qword ptr [esp + 0x10]
            //   e9????????           |                     
            //   db8740010000         | fild                dword ptr [edi + 0x140]
            //   dc6c2418             | fsubr               qword ptr [esp + 0x18]
            //   dd5c2418             | fstp                qword ptr [esp + 0x18]
            //   e9????????           |                     

        $sequence_4 = { 8b8894010000 33d2 85c9 0f95c2 8bc2 c20800 8b90b4010000 }
            // n = 7, score = 100
            //   8b8894010000         | mov                 ecx, dword ptr [eax + 0x194]
            //   33d2                 | xor                 edx, edx
            //   85c9                 | test                ecx, ecx
            //   0f95c2               | setne               dl
            //   8bc2                 | mov                 eax, edx
            //   c20800               | ret                 8
            //   8b90b4010000         | mov                 edx, dword ptr [eax + 0x1b4]

        $sequence_5 = { 8d54b500 8b3c02 8d44f500 83c704 57 50 e8???????? }
            // n = 7, score = 100
            //   8d54b500             | lea                 edx, [ebp + esi*4]
            //   8b3c02               | mov                 edi, dword ptr [edx + eax]
            //   8d44f500             | lea                 eax, [ebp + esi*8]
            //   83c704               | add                 edi, 4
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 85c9 7519 8b54240c 33c9 890a 8b8820010000 894a04 }
            // n = 7, score = 100
            //   85c9                 | test                ecx, ecx
            //   7519                 | jne                 0x1b
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   33c9                 | xor                 ecx, ecx
            //   890a                 | mov                 dword ptr [edx], ecx
            //   8b8820010000         | mov                 ecx, dword ptr [eax + 0x120]
            //   894a04               | mov                 dword ptr [edx + 4], ecx

        $sequence_7 = { 85c0 be???????? 7505 be???????? e8???????? 8b4008 56 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   be????????           |                     
            //   7505                 | jne                 7
            //   be????????           |                     
            //   e8????????           |                     
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   56                   | push                esi

        $sequence_8 = { 8b10 52 e8???????? 83c404 8b4c2474 8901 8d4c2414 }
            // n = 7, score = 100
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4c2474             | mov                 ecx, dword ptr [esp + 0x74]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_9 = { 8903 8965e8 6800000000 6800000000 6800000000 ff75f0 6800000000 }
            // n = 7, score = 100
            //   8903                 | mov                 dword ptr [ebx], eax
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   6800000000           | push                0
            //   6800000000           | push                0
            //   6800000000           | push                0
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   6800000000           | push                0

    condition:
        7 of them and filesize < 5177344
}