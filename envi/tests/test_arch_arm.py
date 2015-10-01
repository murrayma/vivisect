import unittest



('00', 'b'),
('','cbz'),
('','cbnz'),
('','bl'),
('','blx'),
('','blx'),
('','bx'),
('','bxj'),
('','tbb'),
('','tbh'),
('','adc'),
('','add'),
('','adr'),
('','and'),
('','bic'),
('','cmn'),
('','cmp'),
('','eor'),
('','mov'),
('','mvn'),
('','orn'),
('','orr'),
('','rsb'),
('','rsc'),
('','sbc'),
('','sub'),
('','teq'),
('','tst'),
('','asr'),
('','lsl'),
('','lsr'),
('','ror'),
('','rrx'),
('','mla'),
('','mls'),
('','mul'),
('','smlabb'),
('','smlabt'),
('','smlatb'),
('','smlatt'),
('','smlad'),
('','smlal'),
('','smlalbb'),
('','smlalbt'),
('','smlaltt'),
('','smlald'),
('','smlawb'),
('','smlawt'),
('','smlsd'),
('','smlsld,'),
('','smmla'),
('','smmls'),
('','smmul'),
('','smuad'),
('','smulbb'),
('','smulbt'),
('','smultb'),
('','smultt'),
('','smull'),
('','smulwb'),
('','smulwt'),
('','smusd'),
('','umaal'),
('','umlal'),
('','umull'),
('','ssat'),
('','ssat16'),
('','usat'),
('','usat16'),
('','qadd'),
('','qsub'),
('','qdadd'),
('','qdsub'),
('','pkh'),
('','sxtab'),
('','sxtab16'),
('','sxtah'),
('','sxtb'),
('','sxtb16'),
('','sxth'),
('','uxtab'),
('','uxtab16'),
('','uxtah'),
('','uxtb'),
('','uxtb16'),
('','uxth'),
('','sadd16'),
('','qadd16'),
('','shadd16'),
('','uadd16'),
('','uqadd16'),
('','uhadd16'),
('','sasx'),
('','qasx'),
('','shasx'),
('','uasx'),
('','uqasx'),
('','uhasx'),
('','ssax'),
('','qsax'),
('','shsax'),
('','usax'),
('','uqsax'),
('','uhsax'),
('','ssub16'),
('','qsub16'),
('','shsub16'),
('','usub16'),
('','uqsub16'),
('','uhsub16'),
('','sadd8'),
('','qadd8'),
('','shadd8'),
('','uadd8'),
('','uqadd8'),
('','uhadd8'),
('','ssub8'),
('','qsub8'),
('','shsub8'),
('','usub8'),
('','uqsub8'),
('','uhsub8'),
('','sdiv'),
('','udiv'),
('','bfc'),
('','bfi'),
('','clz'),
('','movt'),
('','rbit'),
('','rev'),
('','rev16'),
('','revsh'),
('','sbfx'),
('','sel'),
('','ubfx'),
('','usad8'),
('','usada8'),
('','msr'),
('','mrs'),
('','cps'),
('','ldr'),
('','str'),
('','ldrt'),
('','strt'),
('','ldrex'),
('','strex'),
('','strh'),
('','strht'),
('','strexh'),
('','ldrh'),
('','ldrht'),
('','ldrexh'),
('','ldrsh'),
('','ldrsht'),
('','strb'),
('','strbt'),
('','strexb'),
('','ldrb'),
('','ldrbt'),
('','ldrexb'),
('','ldrsb'),
('','ldrsbt'),
('','ldrd'),
('','strd'),
('','ldrexd'),
('','strexd'),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),
('',''),

class ArmInstructionSet(unittest.TestCase):
    def test_msr(self):
        # test the MSR instruction
        import envi.archs.arm as e_arm;reload(e_arm)
        am=e_arm.ArmModule()
        op = am.archParseOpcode('d3f021e3'.decode('hex'))
        self.assertEqual('msr CPSR_c, #0xd3', repr(op))

