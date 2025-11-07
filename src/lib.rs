pub mod rom;
pub mod cardano;
pub mod persistence;
use rand::Rng;
pub use rom::{RomGenerationType, Rom, RomDigest, hprime};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

// ** Consolidated Imports required for scavenge function **
use std::sync::mpsc::{Sender, channel};
use std::{sync::Arc, thread, time::SystemTime};
use std::sync::atomic::{AtomicBool, Ordering};
use indicatif::{ProgressBar, ProgressStyle};
// ************************************


// 1 byte operator
// 3 bytes operands (src1, src2, dst)
// 28 bytes data
const INSTR_SIZE: usize = 20;
const NB_REGS: usize = 1 << REGS_BITS;
const REGS_BITS: usize = 5;
const REGS_INDEX_MASK: u8 = NB_REGS as u8 - 1;

type Register = u64;

const REGISTER_SIZE: usize = std::mem::size_of::<Register>();

struct VM {
    program: Program,
    regs: [Register; NB_REGS],
    ip: u32,
    prog_digest: blake2b_simd::State,
    mem_digest: blake2b_simd::State,
    prog_seed: [u8; 64],
    memory_counter: u32,
    loop_counter: u32,
}

#[derive(Clone, Copy)]
enum Instr {
    Op3(Op3),
    Op2(Op2),
}

#[derive(Clone, Copy)]
enum Op3 {
    Add,
    Mul,
    MulH,
    Xor,
    Div,
    Mod,
    And,
    Hash(u8),
}

#[derive(Clone, Copy)]
enum Op2 {
    ISqrt,
    Neg,
    BitRev,
    RotL,
    RotR,
}

static INSTR_LUT: [Instr; 256] = {
    let mut lut = [Instr::Op3(Op3::Add); 256];
    let mut i = 0;
    while i <= 255 {
        let instr = match i {
            ..40 => Instr::Op3(Op3::Add),                      // 40
            40..80 => Instr::Op3(Op3::Mul),                    // 40
            80..96 => Instr::Op3(Op3::MulH),                   // 16
            96..112 => Instr::Op3(Op3::Div),                   // 16
            112..128 => Instr::Op3(Op3::Mod),                  // 16
            128..138 => Instr::Op2(Op2::ISqrt),                // 10
            138..148 => Instr::Op2(Op2::BitRev),               // 10
            148..188 => Instr::Op3(Op3::Xor),                  // 40
            188..204 => Instr::Op2(Op2::RotL),                 // 16
            204..220 => Instr::Op2(Op2::RotR),                 // 16
            220..240 => Instr::Op2(Op2::Neg),                  // 20
            240..248 => Instr::Op3(Op3::And),                  // 8
            248.. => Instr::Op3(Op3::Hash(i as u8 - 248)),     // 8
        };
        lut[i as usize] = instr;
        i += 1;
    }
    lut
};

impl From<u8> for Instr {
    fn from(value: u8) -> Self {
        INSTR_LUT[value as usize]
    }
}

#[derive(Clone, Copy)]
enum Operand {
    Reg,
    Memory,
    Literal,
    Special1,
    Special2,
}

static OPERAND_LUT: [Operand; 16] = [
    Operand::Reg,     // 0
    Operand::Reg,     // 1
    Operand::Reg,     // 2
    Operand::Reg,     // 3
    Operand::Reg,     // 4
    Operand::Memory,  // 5
    Operand::Memory,  // 6
    Operand::Memory,  // 7
    Operand::Memory,  // 8
    Operand::Literal, // 9
    Operand::Literal, // 10
    Operand::Literal, // 11
    Operand::Literal, // 12
    Operand::Special1, // 13
    Operand::Special2, // 14
    Operand::Special2, // 15
];

impl From<u8> for Operand {
    fn from(value: u8) -> Self {
        OPERAND_LUT[value as usize]
    }
}

impl VM {
    /// Create a new VM which is specific to the ROM by using the RomDigest,
    /// but mainly dependent on the salt which is an arbitrary byte content
    pub fn new(rom_digest: &RomDigest, nb_instrs: u32, salt: &[u8]) -> Self {
        const DIGEST_INIT_SIZE: usize = 64;
        const REGS_CONTENT_SIZE: usize = REGISTER_SIZE * NB_REGS;

        let mut init_buffer = [0; REGS_CONTENT_SIZE + 3 * DIGEST_INIT_SIZE];

        let mut init_buffer_input = rom_digest.0.to_vec();
        init_buffer_input.extend_from_slice(salt);
        hprime(&mut init_buffer, &init_buffer_input);

        let (init_buffer_regs, init_buffer_digests) = init_buffer.split_at(REGS_CONTENT_SIZE);

        let mut regs = [0; NB_REGS];
        for (reg, reg_bytes) in regs.iter_mut().zip(init_buffer_regs.chunks(REGISTER_SIZE)) {
            *reg = u64::from_le_bytes(*<&[u8; 8]>::try_from(reg_bytes).unwrap());
        }

        let mut digests = init_buffer_digests.chunks(DIGEST_INIT_SIZE);
        let mut prog_digest = blake2b_simd::Params::new().hash_length(64).to_state();
        prog_digest.update(digests.next().unwrap());
        let mut mem_digest = blake2b_simd::Params::new().hash_length(64).to_state();
        mem_digest.update(digests.next().unwrap());
        let prog_seed = *<&[u8; 64]>::try_from(digests.next().unwrap()).unwrap();

        assert_eq!(digests.next(), None);

        let program = Program::new(nb_instrs);

        Self {
            program,
            regs,
            prog_digest,
            mem_digest,
            prog_seed,
            ip: 0,
            loop_counter: 0,
            memory_counter: 0,
        }
    }

    pub fn step(&mut self, rom: &Rom) {
        execute_one_instruction(self, rom);
        self.ip = self.ip.wrapping_add(1);
    }

    fn sum_regs(&self) -> u64 {
        self.regs.iter().fold(0, |acc, r| acc.wrapping_add(*r))
    }

    pub fn post_instructions(&mut self) {
        let sum_regs = self.sum_regs();

        let prog_value = self
            .prog_digest
            .clone()
            .update(&sum_regs.to_le_bytes())
            .finalize();
        let mem_value = self
            .mem_digest
            .clone()
            .update(&sum_regs.to_le_bytes())
            .finalize();

        let mixing_value = blake2b_simd::Params::new().hash_length(64).to_state()
            .update(prog_value.as_array())
            .update(mem_value.as_array())
            .update(&self.loop_counter.to_le_bytes())
            .finalize();
        let mut mixing_out = vec![0; NB_REGS * REGISTER_SIZE * 32];
        hprime(&mut mixing_out, mixing_value.as_array());

        for mem_chunks in mixing_out.chunks(NB_REGS * REGISTER_SIZE) {
            for (reg, reg_chunk) in self.regs.iter_mut().zip(mem_chunks.chunks(8)) {
                *reg ^= u64::from_le_bytes(*<&[u8; 8]>::try_from(reg_chunk).unwrap())
            }
        }

        self.prog_seed = *prog_value.as_array();
        self.loop_counter = self.loop_counter.wrapping_add(1)
    }

    pub fn execute(&mut self, rom: &Rom, instr: u32) {
        self.program.shuffle(&self.prog_seed);
        for _ in 0..instr {
            self.step(rom)
        }
        self.post_instructions()
    }

    pub fn finalize(self) -> [u8; 64] {
        let prog_digest = self.prog_digest.finalize();
        let mem_digest = self.mem_digest.finalize();
        let mut context = blake2b_simd::Params::new().hash_length(64).to_state();
        context.update(prog_digest.as_array());
        context.update(mem_digest.as_array());
        context.update(&self.memory_counter.to_le_bytes());
        for r in self.regs {
            context.update(&r.to_le_bytes());
        }
        *context.finalize().as_array()
    }

    #[allow(dead_code)]
    pub(crate) fn debug(&self) -> String {
        let mut out = String::new();
        for (i, r) in self.regs.iter().enumerate() {
            out.push_str(&format!("[{i:02x}] {r:016x} "));
            if (i % 4) == 3 {
                out.push('\n');
            }
        }
        out.push_str(&format!("ip {:08x}\n", self.ip,));
        out
    }
}

struct Program {
    instructions: Vec<u8>,
}

impl Program {
    pub fn new(nb_instrs: u32) -> Self {
        let size = nb_instrs as usize * INSTR_SIZE;
        let instructions = vec![0; size];
        Self { instructions }
    }

    #[inline]
    pub fn at(&self, i: u32) -> &[u8; INSTR_SIZE] {
        let start = (i as usize).wrapping_mul(INSTR_SIZE) % self.instructions.len();
        <&[u8; INSTR_SIZE]>::try_from(&self.instructions[start..start + INSTR_SIZE]).unwrap()
    }

    pub fn shuffle(&mut self, seed: &[u8; 64]) {
        hprime(&mut self.instructions, seed)
    }
}

#[derive(Clone)]
pub struct Instruction {
    opcode: Instr,
    op1: Operand,
    op2: Operand,
    r1: u8,
    r2: u8,
    r3: u8,
    lit1: u64,
    lit2: u64,
}

#[inline]
fn decode_instruction(instruction: &[u8; INSTR_SIZE]) -> Instruction {
    let opcode = Instr::from(instruction[0]);
    let op1 = Operand::from(instruction[1] >> 4);
    let op2 = Operand::from(instruction[1] & 0x0f);

    let rs = ((instruction[2] as u16) << 8) | (instruction[3] as u16);
    let r1 = ((rs >> (2 * REGS_BITS)) as u8) & REGS_INDEX_MASK;
    let r2 = ((rs >> REGS_BITS) as u8) & REGS_INDEX_MASK;
    let r3 = (rs as u8) & REGS_INDEX_MASK;

    let lit1 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&instruction[4..12]).unwrap());
    let lit2 = u64::from_le_bytes(*<&[u8; 8]>::try_from(&instruction[12..20]).unwrap());

    Instruction {
        opcode,
        op1,
        op2,
        r1,
        r2,
        r3,
        lit1,
        lit2,
    }
}

fn execute_one_instruction(vm: &mut VM, rom: &Rom) {
    let prog_chunk = *vm.program.at(vm.ip);

    macro_rules! mem_access64 {
        ($vm:ident, $rom:ident, $addr:ident) => {{
            let mem = rom.at($addr as u32);
            $vm.mem_digest.update(mem);
            $vm.memory_counter = $vm.memory_counter.wrapping_add(1);

            // divide memory access into 8 chunks of 8 bytes
            let idx = (($vm.memory_counter % (64 / 8)) as usize) * 8;
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&mem[idx..idx + 8]).unwrap())
        }};
    }

    macro_rules! special1_value64 {
        ($vm:ident) => {{
            let r = $vm.prog_digest.clone();
            let h = r.finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&h.as_array()[0..8]).unwrap())
        }};
    }

    macro_rules! special2_value64 {
        ($vm:ident) => {{
            let r = $vm.mem_digest.clone();
            let h = r.finalize();
            u64::from_le_bytes(*<&[u8; 8]>::try_from(&h.as_array()[0..8]).unwrap())
        }};
    }

    let Instruction {
        opcode,
        op1,
        op2,
        r1,
        r2,
        r3,
        lit1,
        lit2,
    } = decode_instruction(&prog_chunk);

    match opcode {
        Instr::Op3(operator) => {
            let src1 = match op1 {
                Operand::Reg => vm.regs[r1 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Literal => lit1,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };
            let src2 = match op2 {
                Operand::Reg => vm.regs[r2 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit2),
                Operand::Literal => lit2,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op3::Add => src1.wrapping_add(src2),
                Op3::Mul => src1.wrapping_mul(src2),
                Op3::MulH => ((src1 as u128 * src2 as u128) >> 64) as u64,
                Op3::Xor => src1 ^ src2,
                Op3::Div => {
                    if src2 == 0 {
                        special1_value64!(vm)
                    } else {
                        src1 / src2
                    }
                }
                Op3::Mod => {
                    if src2 == 0 {
                        special1_value64!(vm)
                    } else {
                        src1 / src2
                    }
                }
                Op3::And => src1 & src2,
                Op3::Hash(v) => {
                    assert!(v < 8);
                    let out = blake2b_simd::Params::new().hash_length(64).to_state()
                        .update(&src1.to_le_bytes())
                        .update(&src2.to_le_bytes())
                        .finalize();
                    if let Some(chunk) = out.as_array().chunks(8).nth(v as usize) {
                        u64::from_le_bytes(*<&[u8; 8]>::try_from(chunk).unwrap())
                    } else {
                        panic!("chunk doesn't exist")
                    }
                }
            };

            vm.regs[r3 as usize] = result;
        }
        Instr::Op2(operator) => {
            let src1 = match op1 {
                Operand::Reg => vm.regs[r1 as usize],
                Operand::Memory => mem_access64!(vm, rom, lit1),
                Operand::Literal => lit1,
                Operand::Special1 => special1_value64!(vm),
                Operand::Special2 => special2_value64!(vm),
            };

            let result = match operator {
                Op2::Neg => !src1,
                Op2::RotL => src1.rotate_left(r1 as u32),
                Op2::RotR => src1.rotate_right(r1 as u32),
                Op2::ISqrt => src1.isqrt(),
                Op2::BitRev => src1.reverse_bits(),
            };
            vm.regs[r3 as usize] = result;
        }
    }
    vm.prog_digest.update(&prog_chunk);
}

#[inline]
pub fn hash(salt: &[u8], rom: &Rom, nb_loops: u32, nb_instrs: u32) -> [u8; 64] {
    let mut vm = VM::new(&rom.digest, nb_instrs, salt);
    for _ in 0..nb_loops {
        vm.execute(rom, nb_instrs);
    }
    vm.finalize()
}

#[inline]
pub fn hash_structure_good(hash: &[u8], difficulty_mask: u32) -> bool {
    let value = u32::from_be_bytes(hash[..4].try_into().unwrap());
    (value | difficulty_mask) == difficulty_mask
}

// --------------------------------------------------------------------------
// SCAVENGE LOGIC
// --------------------------------------------------------------------------

pub struct Thread {}

// Structure to hold dynamic challenge parameters from the API
#[derive(Clone)]
pub struct ChallengeParams {
    pub rom_key: String, // no_pre_mine hex string (used for ROM init)
    pub difficulty_mask: u32, // difficulty mask (used for submission check)
    pub address: String, // Registered Cardano address
    pub challenge_id: String,
    pub latest_submission: String,
    pub no_pre_mine_hour: String,
    pub rom: Arc<Rom>,
}

#[derive(Clone)]
pub enum Result {
    Progress(usize),
    Found(u64, [u8; 64]), // Found now returns the nonce AND the 64-byte hash
}

// Helper to build the preimage string as specified in the API documentation
pub fn build_preimage(
    nonce: u64,
    address: &str,
    challenge_id: &str,
    difficulty_mask: u32,
    no_pre_mine: &str,
    latest_submission: &str,
    no_pre_mine_hour: &str,
) -> String {
    let nonce_hex = format!("{:016x}", nonce);
    let mut preimage = String::new();
    preimage.push_str(&nonce_hex);
    preimage.push_str(address);
    preimage.push_str(challenge_id);
    preimage.push_str(&format!("{:08X}", difficulty_mask));
    preimage.push_str(no_pre_mine);
    preimage.push_str(latest_submission);
    preimage.push_str(no_pre_mine_hour);
    preimage
}

#[inline]
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn update_preimage_nonce(preimage_bytes: &mut [u8], nonce: u64) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut n = nonce;
    // NOTE: Since our nonce is small, only update last 8 bytes
    for i in (8..16).rev() {
        let nibble = (n & 0xF) as usize;
        preimage_bytes[i] = HEX_CHARS[nibble];
        n >>= 4;
    }
}

#[inline]
#[cfg(target_arch = "x86_64")]
fn update_preimage_nonce(preimage_bytes: &mut [u8], nonce: u64) {
    unsafe {
        let hex_chars = _mm_loadu_si128(b"0123456789abcdef".as_ptr() as *const _);
        let nonce_vec = _mm_loadl_epi64(nonce.to_be_bytes().as_ptr() as *const _);
        let nibble_mask = _mm_set1_epi8(0x0F);
        let indices_lo = _mm_and_si128(nonce_vec, nibble_mask);
        let indices_hi = _mm_and_si128(_mm_srli_epi64(nonce_vec, 4), nibble_mask);
        let indices = _mm_unpacklo_epi8(indices_hi, indices_lo);
        let result_vec = _mm_shuffle_epi8(hex_chars, indices);
        _mm_storeu_si128(preimage_bytes.as_mut_ptr() as *mut _, result_vec);
    }
}

#[inline]
#[cfg(target_arch = "aarch64")]
fn update_preimage_nonce(preimage_bytes: &mut [u8], nonce: u64) {
    unsafe {
        let hex_chars = vld1q_u8(b"0123456789abcdef".as_ptr() as *const _);
        let nonce_vec = vld1_u8(nonce.to_be_bytes().as_ptr() as *const _);
        let nibble_mask = vdup_n_u8(0x0F);
        let indices_hi = vshr_n_u8(nonce_vec, 4);
        let indices_lo = vand_u8(nonce_vec, nibble_mask);
        let half1 = vzip1_u8(indices_hi, indices_lo);
        let half2 = vzip2_u8(indices_hi, indices_lo);
        let indices = vcombine_u8(half1, half2);
        let result_vec = vqtbl1q_u8(hex_chars, indices);
        vst1q_u8(preimage_bytes.as_mut_ptr() as *mut _, result_vec);
    }
}

// The worker thread function
pub fn spin(params: ChallengeParams, sender: Sender<Result>, stop_signal: Arc<AtomicBool>, start_nonce: u64, step_size: u64) {
    let mut nonce_value = start_nonce;
    const CHUNKS_SIZE: usize = 0xff;
    const NB_LOOPS: u32 = 8;
    const NB_INSTRS: u32 = 256;

    let preimage_string = build_preimage(
        nonce_value,
        &params.address,
        &params.challenge_id,
        params.difficulty_mask,
        &params.rom_key,
        &params.latest_submission,
        &params.no_pre_mine_hour,
    );
    let mut preimage_bytes = preimage_string.into_bytes();

    while !stop_signal.load(Ordering::Relaxed) {
        let h = hash(&preimage_bytes, &params.rom, NB_LOOPS, NB_INSTRS);

        if hash_structure_good(&h, params.difficulty_mask) {
            if sender.send(Result::Found(nonce_value, h)).is_ok() {
                // Sent the found nonce
            }
            return;
        }

        if nonce_value & (CHUNKS_SIZE as u64) == 0 && sender.send(Result::Progress(CHUNKS_SIZE)).is_err() {
             return;
        }

        // Increment nonce by the thread step size
        nonce_value = nonce_value.wrapping_add(step_size);
        update_preimage_nonce(&mut preimage_bytes[0..16], nonce_value);
    }
}

// The main orchestration function
pub fn scavenge(
    my_registered_address: String,
    challenge_id: String,
    difficulty: String,
    no_pre_mine_key: String,
    latest_submission: String,
    no_pre_mine_hour: String,
    nb_threads: u32,
) -> (Option<String>, u64, f64) { // <-- FIX: Explicitly define the return type
    const MB: usize = 1024 * 1024;
    const GB: usize = 1024 * MB;

    let difficulty_mask = u32::from_str_radix(&difficulty, 16).unwrap();

    let nb_threads_u64 = nb_threads as u64;
    let step_size = nb_threads_u64;

    let (found_nonce, final_hashes_checked, elapsed_time) = thread::scope(|s| {
        println!("Generating ROM with key: {}", no_pre_mine_key);

        let rom = Rom::new(
            no_pre_mine_key.as_bytes(),
            RomGenerationType::TwoStep {
                pre_size: 16 * MB,
                mixing_numbers: 4,
            },
            GB,
        );
        println!("{}", rom.digest);

        let (sender, receiver) = channel();
        let stop_signal = Arc::new(AtomicBool::new(false));

        let common_params = ChallengeParams {
            rom_key: no_pre_mine_key.clone(),
            difficulty_mask,
            address: my_registered_address.clone(),
            challenge_id: challenge_id.clone(),
            latest_submission: latest_submission.clone(),
            no_pre_mine_hour: no_pre_mine_hour.clone(),
            rom: Arc::new(rom),
        };
        let mut rng = rand::rng();
        let start_nonce: u64 = rng.random_range(0x00..0xFF) << 16;

        for thread_id in 0..nb_threads_u64 {
            let params = common_params.clone();
            let sender = sender.clone();
            let stop_signal = stop_signal.clone();

            s.spawn(move || {
                spin(params, sender, stop_signal, start_nonce + thread_id, step_size)
            });
        }

        // Drop the extra sender handle in the main thread to ensure the receiver loop terminates
        drop(sender);

        let start_loop = SystemTime::now();
        let mut pos = 0;
        let pb = ProgressBar::new(u64::MAX);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {pos}/{len} [{elapsed_precise}] {bar:40.cyan/blue} {msg}",
            )
            .unwrap()
            .progress_chars("#>-"),
        );

        let mut found = Vec::new();
        let mut should_stop_after_found = false;

        // Use a loop that waits for channel messages until all senders are dropped
        while let Ok(r) = receiver.recv() {
            match r {
                Result::Progress(sz) => {
                    if should_stop_after_found {
                        // Ignore progress messages if we've already found a solution and are waiting for threads to exit.
                        continue;
                    }

                    pos += sz as u64;
                    pb.set_position(pos);
                    let elapsed = start_loop.elapsed().unwrap().as_secs_f64();
                    let current_speed = (pos as f64) / elapsed;

                    pb.set_message(format!(
                        "Speed: {:.2} hash/s found: {}",
                        current_speed,
                        found.len()
                    ));
                }
                Result::Found(nonce, _h_output) => {
                    let nonce_hex = format!("{:016x}", nonce);
                    println!("\nFound valid nonce: {}", nonce_hex);
                    found.push(nonce);

                    // 🚨 Signal all worker threads to stop gracefully
                    stop_signal.store(true, Ordering::Relaxed);
                    should_stop_after_found = true;
                    // The loop continues, draining any remaining messages before recv() returns Err(RecvError::Disconnected)
                }
            }
        }

        // Final message after the mining stops (channel disconnects)
        let final_nonce_hex = found.pop().map(|nonce| format!("{:016x}", nonce));
        let final_elapsed = start_loop.elapsed().unwrap().as_secs_f64();
        let final_hashes = pos;

        if final_nonce_hex.is_some() {
            let msg = format!("Scavenging complete. Found 1 solution. Total hashes checked: {}", pos);
            pb.finish_with_message(msg);
        } else {
             pb.abandon_with_message("Scavenging stopped (No solution found).");
        }

        // Return the found nonce (if any) from the thread scope
        (final_nonce_hex, final_hashes, final_elapsed)
    });

    (found_nonce, final_hashes_checked, elapsed_time)
}
