use std::fmt;

use crate::bpf::instruction::Reg;

/// Tracks the known bits of a scalar, inspired by the kernel's tnum (tracked number).
///
/// `value` holds bits known to be 1. `mask` holds bits that are unknown.
/// Known-zero bits have value=0, mask=0. Known-one bits have value=1, mask=0.
/// Unknown bits have mask=1 (value is ignored for those bits).
///
/// Invariant: value & mask == 0 (known bits are reflected in value, not mask).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}

impl Tnum {
    /// A fully known constant.
    pub fn constant(v: u64) -> Self {
        Self { value: v, mask: 0 }
    }

    /// Completely unknown 64-bit value.
    pub fn unknown() -> Self {
        Self {
            value: 0,
            mask: u64::MAX,
        }
    }

    /// Whether this tnum represents a single known value.
    pub fn is_known(&self) -> bool {
        self.mask == 0
    }

    /// If fully known, return the concrete value.
    pub fn known_value(&self) -> Option<u64> {
        if self.is_known() {
            Some(self.value)
        } else {
            None
        }
    }

    /// AND of two tnums (kernel formulation).
    pub fn and(self, other: Tnum) -> Tnum {
        let alpha = self.value | self.mask;
        let beta = other.value | other.mask;
        let v = self.value & other.value;
        let mu = alpha & beta & !v;
        Tnum {
            value: v,
            mask: mu,
        }
    }

    /// OR of two tnums.
    pub fn or(self, other: Tnum) -> Tnum {
        let v = self.value | other.value;
        let mu = (self.mask | other.mask) & !v;
        Tnum {
            value: v,
            mask: mu,
        }
    }

    /// XOR of two tnums.
    pub fn xor(self, other: Tnum) -> Tnum {
        let v = self.value ^ other.value;
        let mu = self.mask | other.mask;
        Tnum {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Left shift by a known amount. Shifts >= 64 produce zero.
    pub fn lsh(self, shift: u32) -> Tnum {
        if shift >= 64 {
            return Tnum::constant(0);
        }
        Tnum {
            value: self.value << shift,
            mask: self.mask << shift,
        }
    }

    /// Logical right shift by a known amount. Shifts >= 64 produce zero.
    pub fn rsh(self, shift: u32) -> Tnum {
        if shift >= 64 {
            return Tnum::constant(0);
        }
        Tnum {
            value: self.value >> shift,
            mask: self.mask >> shift,
        }
    }

    /// SUB of two tnums: self - other.
    pub fn sub(self, other: Tnum) -> Tnum {
        // From kernel: tnum_sub is computed as tnum_add(a, tnum { -b.value, b.mask }).
        let neg_other = Tnum {
            value: other.value.wrapping_neg(),
            mask: other.mask,
        };
        self.add(neg_other)
    }

    /// ADD of two tnums.
    pub fn add(self, other: Tnum) -> Tnum {
        // From kernel: sm = a.mask + b.mask, sv = a.value + b.value, sigma = sm + sv
        let sv = self.value.wrapping_add(other.value);
        let sm = self.mask.wrapping_add(other.mask);
        let sigma = sv.wrapping_add(sm);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | other.mask;
        Tnum {
            value: sv & !mu,
            mask: mu,
        }
    }

    /// Truncate to 32 bits (upper 32 bits become known-zero).
    pub fn trunc32(self) -> Tnum {
        Tnum {
            value: self.value & 0xFFFF_FFFF,
            mask: self.mask & 0xFFFF_FFFF,
        }
    }

    /// Possible minimum value.
    pub fn min_value(self) -> u64 {
        self.value
    }

    /// Possible maximum value.
    pub fn max_value(self) -> u64 {
        self.value | self.mask
    }
}

impl fmt::Display for Tnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_known() {
            write!(f, "{}", self.value)
        } else {
            write!(f, "(val={:#x}, mask={:#x})", self.value, self.mask)
        }
    }
}

/// The type of value held in a register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegType {
    /// Not yet written -- reading is an error.
    Uninit,
    /// A scalar value (not a pointer). Tracked via tnum + range bounds.
    Scalar,
    /// Pointer to the 512-byte stack frame. `offset` is the known constant offset from r10.
    FramePtr { offset: i64 },
    /// Pointer to a map value returned by map_lookup_elem. `id` distinguishes different lookups.
    /// `size` is the map value size (if known from BTF/map def).
    /// `origin_pc` is the helper call that created this pointer.
    MapValuePtr { id: usize, offset: i64, size: u32, origin_pc: usize },
    /// Pointer to the programme context (r1 at entry).
    CtxPtr { offset: i64 },
    /// Pointer to ring buffer reservation.
    /// `origin_pc` is the ringbuf_reserve call that created this pointer.
    RingBufPtr { id: usize, offset: i64, size: u32, origin_pc: usize },
    /// Pointer into kernel memory (loaded from ctx or via CO-RE field access).
    /// Dereferencing a KernelPtr yields another KernelPtr, modelling the
    /// chained field accesses in BPF_CORE_READ.
    KernelPtr,
    /// Pointer to a global data section (.rodata, .data, .bss, or a global
    /// variable). These are patched in by the loader at load time from
    /// LD_IMM64 relocations.
    DataPtr { name: String },
    /// Pointer that might be null (before null check).
    /// `origin_pc` is the collapsed instruction index of the helper call
    /// that produced this pointer, used for diagnostic messages.
    /// `id` uniquely identifies this nullable allocation so that when one
    /// register is null-checked, all registers sharing the same id are
    /// refined on both branches.
    PtrOrNull { inner: Box<RegType>, origin_pc: Option<usize>, id: usize },
    /// Known null value (after a null-check on the null branch).
    Null,
}

impl RegType {
    /// Whether this type is some kind of valid pointer (not null, not scalar, not uninit).
    pub fn is_ptr(&self) -> bool {
        matches!(
            self,
            RegType::FramePtr { .. }
                | RegType::MapValuePtr { .. }
                | RegType::CtxPtr { .. }
                | RegType::RingBufPtr { .. }
                | RegType::KernelPtr
                | RegType::DataPtr { .. }
        )
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            RegType::Uninit => "uninit",
            RegType::Scalar => "scalar",
            RegType::FramePtr { .. } => "frame_ptr",
            RegType::MapValuePtr { .. } => "map_value_ptr",
            RegType::CtxPtr { .. } => "ctx_ptr",
            RegType::RingBufPtr { .. } => "ringbuf_ptr",
            RegType::KernelPtr => "kernel_ptr",
            RegType::DataPtr { .. } => "data_ptr",
            RegType::PtrOrNull { .. } => "ptr_or_null",
            RegType::Null => "null",
        }
    }
}

impl fmt::Display for RegType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegType::Uninit => write!(f, "uninit"),
            RegType::Scalar => write!(f, "scalar"),
            RegType::FramePtr { offset } => write!(f, "fp{offset:+}"),
            RegType::MapValuePtr { id, offset, size, .. } => {
                write!(f, "map_value(id={id}, off={offset}, size={size})")
            }
            RegType::CtxPtr { offset } => write!(f, "ctx{offset:+}"),
            RegType::RingBufPtr { id, offset, size, .. } => {
                write!(f, "ringbuf(id={id}, off={offset}, size={size})")
            }
            RegType::KernelPtr => write!(f, "kernel_ptr"),
            RegType::DataPtr { name } => write!(f, "data_ptr({name})"),
            RegType::PtrOrNull { inner, .. } => write!(f, "{inner}_or_null"),
            RegType::Null => write!(f, "null"),
        }
    }
}

/// Full state of a single register: type + scalar bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegState {
    pub reg_type: RegType,
    /// Tracked number for scalar range analysis.
    pub tnum: Tnum,
    /// Signed bounds.
    pub smin: i64,
    pub smax: i64,
    /// Unsigned bounds.
    pub umin: u64,
    pub umax: u64,
}

impl RegState {
    pub fn uninit() -> Self {
        Self {
            reg_type: RegType::Uninit,
            tnum: Tnum::unknown(),
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
        }
    }

    pub fn scalar_unknown() -> Self {
        Self {
            reg_type: RegType::Scalar,
            tnum: Tnum::unknown(),
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
        }
    }

    pub fn scalar_value(v: u64) -> Self {
        Self {
            reg_type: RegType::Scalar,
            tnum: Tnum::constant(v),
            smin: v as i64,
            smax: v as i64,
            umin: v,
            umax: v,
        }
    }

    pub fn frame_ptr(offset: i64) -> Self {
        Self {
            reg_type: RegType::FramePtr { offset },
            tnum: Tnum::unknown(),
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
        }
    }

    pub fn ctx_ptr(offset: i64) -> Self {
        Self {
            reg_type: RegType::CtxPtr { offset },
            tnum: Tnum::unknown(),
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
        }
    }

    pub fn kernel_ptr() -> Self {
        Self {
            reg_type: RegType::KernelPtr,
            tnum: Tnum::unknown(),
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
        }
    }

    pub fn null() -> Self {
        Self {
            reg_type: RegType::Null,
            tnum: Tnum::constant(0),
            smin: 0,
            smax: 0,
            umin: 0,
            umax: 0,
        }
    }

    /// Tighten bounds bidirectionally after learning new information
    /// from tnum, unsigned bounds, or signed bounds.
    pub fn refine_bounds(&mut self) {
        // Step 1: tighten unsigned bounds from tnum.
        let tmin = self.tnum.min_value();
        let tmax = self.tnum.max_value();
        self.umin = self.umin.max(tmin);
        self.umax = self.umax.min(tmax);

        // Step 2: if unsigned range collapses, tighten tnum.
        if self.umin == self.umax {
            self.tnum = Tnum::constant(self.umin);
        }

        // Step 3: tighten signed from unsigned (when the unsigned range
        // doesn't straddle the signed boundary).
        if self.umin <= i64::MAX as u64 && self.umax <= i64::MAX as u64 {
            // Entire range is non-negative in signed interpretation.
            self.smin = self.smin.max(self.umin as i64);
            self.smax = self.smax.min(self.umax as i64);
        }

        // Step 4: tighten unsigned from signed (when the signed range
        // is entirely non-negative).
        if self.smin >= 0 {
            self.umin = self.umin.max(self.smin as u64);
            self.umax = self.umax.min(self.smax as u64);
        }

        // Step 5: final collapse check.
        if self.umin == self.umax {
            self.tnum = Tnum::constant(self.umin);
            self.smin = self.umin as i64;
            self.smax = self.umin as i64;
        }
    }

    /// Whether we can read this register (not uninit).
    pub fn is_readable(&self) -> bool {
        self.reg_type != RegType::Uninit
    }
}

impl fmt::Display for RegState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reg_type)?;
        if self.reg_type == RegType::Scalar && !self.tnum.is_known() {
            write!(
                f,
                " u=[{},{}] s=[{},{}]",
                self.umin, self.umax, self.smin, self.smax
            )?;
        }
        Ok(())
    }
}

impl RegState {
    /// Widen two register states into a single state that's a sound
    /// overapproximation of both. Used at back-edge targets (loop heads)
    /// to compute fixed points.
    ///
    /// When types differ, keeps `self` (the established loop head state).
    /// Registers that change type between iterations are set between the
    /// loop head and the back-edge, so the loop head's type is what the
    /// loop body sees on entry. Widening to scalar would destroy pointer
    /// types for goto/retry patterns where unrelated code jumps back.
    pub fn widen(&self, other: &RegState) -> RegState {
        if self.reg_type != other.reg_type {
            if self.reg_type == RegType::Uninit || other.reg_type == RegType::Uninit {
                return RegState::uninit();
            }
            // Different non-uninit types: keep self (the loop entry state).
            return self.clone();
        }

        // Same type: widen the bounds.
        match &self.reg_type {
            RegType::Scalar => {
                let tnum = Tnum {
                    value: self.tnum.value & other.tnum.value,
                    mask: self.tnum.mask | other.tnum.mask
                        | (self.tnum.value ^ other.tnum.value),
                };
                let mut result = RegState {
                    reg_type: RegType::Scalar,
                    tnum,
                    smin: self.smin.min(other.smin),
                    smax: self.smax.max(other.smax),
                    umin: self.umin.min(other.umin),
                    umax: self.umax.max(other.umax),
                };
                result.refine_bounds();
                result
            }
            // Same pointer type: keep if offsets match, else demote.
            // We've already checked self.reg_type == other.reg_type above.
            _ => {
                if self.reg_type == other.reg_type {
                    self.clone()
                } else {
                    RegState::scalar_unknown()
                }
            }
        }
    }

    /// Whether `self` is a substate of `other` (i.e. `other` is at least
    /// as general as `self`). Used for fixed-point detection at loop heads.
    pub fn is_substate_of(&self, other: &RegState) -> bool {
        if self.reg_type == RegType::Uninit {
            return other.reg_type == RegType::Uninit;
        }
        if other.reg_type == RegType::Uninit {
            return false;
        }
        if self.reg_type != other.reg_type {
            return false;
        }
        if self.reg_type == RegType::Scalar {
            self.umin >= other.umin
                && self.umax <= other.umax
                && self.smin >= other.smin
                && self.smax <= other.smax
                && (self.tnum.mask & !other.tnum.mask) == 0
                && (self.tnum.value & !other.tnum.mask) == (other.tnum.value & !other.tnum.mask)
        } else {
            true // same non-scalar type -> substate
        }
    }
}

/// The full verifier state at a programme point: all 11 registers.
#[derive(Debug, Clone)]
pub struct VerifierState {
    pub regs: [RegState; 11],
}

impl VerifierState {
    /// Initial state at programme entry: r1 = ctx, r10 = fp, rest uninit.
    pub fn entry() -> Self {
        let mut regs: [RegState; 11] = std::array::from_fn(|_| RegState::uninit());
        regs[1] = RegState::ctx_ptr(0);
        regs[10] = RegState::frame_ptr(0);
        Self { regs }
    }

    pub fn get(&self, reg: Reg) -> &RegState {
        &self.regs[reg.index() as usize]
    }

    pub fn get_mut(&mut self, reg: Reg) -> &mut RegState {
        &mut self.regs[reg.index() as usize]
    }

    pub fn set(&mut self, reg: Reg, state: RegState) {
        self.regs[reg.index() as usize] = state;
    }

    /// Widen all registers: produce a state that's a sound overapproximation
    /// of both `self` and `other`.
    pub fn widen(&self, other: &VerifierState) -> VerifierState {
        let regs = std::array::from_fn(|i| self.regs[i].widen(&other.regs[i]));
        VerifierState { regs }
    }

    /// Whether `self` is a substate of `other` for all registers.
    pub fn is_substate_of(&self, other: &VerifierState) -> bool {
        self.regs.iter().zip(other.regs.iter()).all(|(a, b)| a.is_substate_of(b))
    }
}

/// What a stack slot contains.
#[derive(Debug, Clone, PartialEq)]
pub enum SlotState {
    /// Not yet written.
    Uninit,
    /// Contains scalar data of the given width.
    Scalar { width: u8 },
    /// Contains a spilled register (pointer type preserved).
    Spill(RegState),
}

/// The 512-byte BPF stack, tracked per-byte for initialisation.
///
/// The stack is addressed as negative offsets from r10 (frame pointer).
/// Offset -1 is stack[511], offset -512 is stack[0].
#[derive(Debug, Clone)]
pub struct StackState {
    /// Per-byte initialisation: true = written, false = uninitialised.
    init: [bool; 512],
    /// Spilled register info, keyed by the aligned offset (for 8-byte spills).
    spills: std::collections::HashMap<i64, RegState>,
}

impl Default for StackState {
    fn default() -> Self {
        Self {
            init: [false; 512],
            spills: std::collections::HashMap::new(),
        }
    }
}

impl StackState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convert a frame-pointer-relative offset to a stack array index.
    /// r10 + offset where offset is negative: stack_idx = 512 + offset.
    fn to_index(offset: i64) -> Option<usize> {
        let idx = 512 + offset;
        if (0..512).contains(&idx) {
            Some(idx as usize)
        } else {
            None
        }
    }

    /// Mark bytes as initialised after a store.
    pub fn mark_written(&mut self, offset: i64, width: u8) {
        for i in 0..width as i64 {
            if let Some(idx) = Self::to_index(offset + i) {
                self.init[idx] = true;
            }
        }
    }

    /// Check that all bytes in the range are initialised (for a load).
    pub fn check_readable(&self, offset: i64, width: u8) -> bool {
        (0..width as i64).all(|i| {
            Self::to_index(offset + i).is_some_and(|idx| self.init[idx])
        })
    }

    /// Check that the access is within the 512-byte stack.
    pub fn check_bounds(offset: i64, width: u8) -> bool {
        let start = 512 + offset;
        let end = start + width as i64;
        start >= 0 && end <= 512
    }

    /// Spill a register to the stack (8-byte aligned store).
    pub fn spill(&mut self, offset: i64, reg: &RegState) {
        self.mark_written(offset, 8);
        self.spills.insert(offset, reg.clone());
    }

    /// Retrieve a spilled register.
    pub fn get_spill(&self, offset: i64) -> Option<&RegState> {
        self.spills.get(&offset)
    }

    /// Clear a spill (e.g. when overwriting with a non-8-byte store).
    pub fn clear_spill(&mut self, offset: i64) {
        self.spills.remove(&offset);
    }

    /// Whether `self` is a substate of `other` for stack initialisation.
    /// True when every byte initialised in `other` is also initialised in `self`
    /// (i.e., `self` has at least as much written as `other`).
    pub fn is_substate_of(&self, other: &StackState) -> bool {
        for i in 0..512 {
            if other.init[i] && !self.init[i] {
                return false;
            }
        }
        true
    }

    /// Widen two stack states: a byte is initialised only if it's
    /// initialised in both states. Spills are kept only if identical.
    pub fn widen(&self, other: &StackState) -> StackState {
        let mut init = [false; 512];
        for (i, slot) in init.iter_mut().enumerate() {
            *slot = self.init[i] && other.init[i];
        }
        let mut spills = std::collections::HashMap::new();
        for (offset, reg) in &self.spills {
            if let Some(other_reg) = other.spills.get(offset) {
                if reg == other_reg {
                    spills.insert(*offset, reg.clone());
                }
            }
        }
        StackState { init, spills }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tnum_constant() {
        let t = Tnum::constant(42);
        assert!(t.is_known());
        assert_eq!(t.known_value(), Some(42));
        assert_eq!(t.min_value(), 42);
        assert_eq!(t.max_value(), 42);
    }

    #[test]
    fn tnum_unknown_range() {
        let t = Tnum::unknown();
        assert!(!t.is_known());
        assert_eq!(t.min_value(), 0);
        assert_eq!(t.max_value(), u64::MAX);
    }

    #[test]
    fn tnum_add_constants() {
        let a = Tnum::constant(10);
        let b = Tnum::constant(20);
        let c = a.add(b);
        assert_eq!(c.known_value(), Some(30));
    }

    #[test]
    fn tnum_and_constants() {
        let a = Tnum::constant(0xFF);
        let b = Tnum::constant(0x0F);
        let c = a.and(b);
        assert_eq!(c.known_value(), Some(0x0F));
    }

    #[test]
    fn tnum_trunc32() {
        let t = Tnum::constant(0x1_0000_0042);
        let t32 = t.trunc32();
        assert_eq!(t32.known_value(), Some(0x42));
    }

    #[test]
    fn stack_bounds_check() {
        assert!(StackState::check_bounds(-8, 8));
        assert!(StackState::check_bounds(-512, 8));
        assert!(!StackState::check_bounds(-513, 8));
        assert!(!StackState::check_bounds(0, 1));
        assert!(StackState::check_bounds(-1, 1));
    }

    #[test]
    fn stack_init_tracking() {
        let mut stack = StackState::new();
        assert!(!stack.check_readable(-8, 8));
        stack.mark_written(-8, 8);
        assert!(stack.check_readable(-8, 8));
        assert!(!stack.check_readable(-16, 8));
    }

    #[test]
    fn verifier_state_entry() {
        let state = VerifierState::entry();
        assert_eq!(state.get(Reg::R1).reg_type, RegType::CtxPtr { offset: 0 });
        assert_eq!(
            state.get(Reg::R10).reg_type,
            RegType::FramePtr { offset: 0 }
        );
        assert_eq!(state.get(Reg::R0).reg_type, RegType::Uninit);
        assert_eq!(state.get(Reg::R6).reg_type, RegType::Uninit);
    }

    #[test]
    fn scalar_refine_bounds() {
        let mut r = RegState::scalar_unknown();
        r.umin = 5;
        r.umax = 10;
        r.refine_bounds();
        assert_eq!(r.smin, 5);
        assert_eq!(r.smax, 10);
    }

    #[test]
    fn scalar_known_collapses_tnum() {
        let mut r = RegState::scalar_unknown();
        r.umin = 42;
        r.umax = 42;
        r.refine_bounds();
        assert_eq!(r.tnum.known_value(), Some(42));
    }

    #[test]
    fn widen_same_scalar_widens_bounds() {
        let a = RegState::scalar_value(3);
        let b = RegState::scalar_value(7);
        let w = a.widen(&b);
        assert_eq!(w.reg_type, RegType::Scalar);
        assert_eq!(w.umin, 3);
        assert_eq!(w.umax, 7);
    }

    #[test]
    fn widen_different_types_becomes_scalar() {
        let a = RegState::scalar_value(0);
        let b = RegState::ctx_ptr(0);
        let w = a.widen(&b);
        assert_eq!(w.reg_type, RegType::Scalar);
    }

    #[test]
    fn widen_uninit_stays_uninit() {
        let a = RegState::uninit();
        let b = RegState::scalar_value(5);
        let w = a.widen(&b);
        assert_eq!(w.reg_type, RegType::Uninit);
    }

    #[test]
    fn substate_known_within_wider_range() {
        let narrow = RegState::scalar_value(5);
        let mut wide = RegState::scalar_unknown();
        wide.umin = 0;
        wide.umax = 10;
        wide.smin = 0;
        wide.smax = 10;
        wide.tnum = Tnum::unknown();
        assert!(narrow.is_substate_of(&wide));
        assert!(!wide.is_substate_of(&narrow));
    }

    #[test]
    fn substate_same_is_substate() {
        let a = RegState::scalar_value(42);
        assert!(a.is_substate_of(&a));
    }

    #[test]
    fn widen_verifier_state() {
        let mut s1 = VerifierState::entry();
        let mut s2 = VerifierState::entry();
        s1.set(Reg::R0, RegState::scalar_value(0));
        s2.set(Reg::R0, RegState::scalar_value(4));
        let w = s1.widen(&s2);
        assert_eq!(w.get(Reg::R0).reg_type, RegType::Scalar);
        assert_eq!(w.get(Reg::R0).umin, 0);
        assert_eq!(w.get(Reg::R0).umax, 4);
    }

    #[test]
    fn stack_widen_intersection() {
        let mut s1 = StackState::new();
        let mut s2 = StackState::new();
        s1.mark_written(-8, 8);
        s1.mark_written(-16, 8);
        s2.mark_written(-8, 8);
        // Only -8 is written in both.
        let w = s1.widen(&s2);
        assert!(w.check_readable(-8, 8));
        assert!(!w.check_readable(-16, 8));
    }
}
