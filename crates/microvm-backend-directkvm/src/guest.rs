//! The tiny educational guest and its x86_64 long-mode boot layout.
//!
//! The guest does exactly one thing: it writes the marker byte `0x4B` (`'K'`)
//! to I/O port `0x3F8` (the 16550 UART data register) and then executes `HLT`.
//! The host observes the port-I/O exit, records the marker, and sees the HLT.
//!
//! To run that guest the vCPU is placed in 64-bit long mode before the first
//! `KVM_RUN`: an identity-mapped page table (2 MiB pages), a minimal GDT with a
//! 64-bit code segment, and the control registers / `EFER` MSRs are programmed
//! via `KVM_SET_SREGS` + `KVM_SET_REGS`.
//!
//! Every byte produced here is pure and deterministic (no host access), so
//! the guest image and boot layout are unit-tested in the default no-feature
//! lane. The privileged runner copies [`write_boot_layout`] output into the
//! identity-mapped memory slot (index == guest physical address).

use crate::{GUEST_MARKER_BYTE, SERIAL_PORT};

// ---------------------------------------------------------------------------
// Guest physical address map (identity-mapped: GPA == offset in the slot)
// ---------------------------------------------------------------------------

/// Guest code is placed at the reset vector, GPA 0.
pub const CODE_GPA: u64 = 0x0000;
/// PML4 (page-map level 4) table base.
pub const PML4_GPA: u64 = 0x1000;
/// PDPT (page-directory-pointer table) base.
pub const PDPT_GPA: u64 = 0x2000;
/// PD (page directory, 2 MiB pages) base.
pub const PD_GPA: u64 = 0x3000;
/// GDT base.
pub const GDT_GPA: u64 = 0x4000;
/// Initial stack pointer (the marker guest does not actually use the stack).
pub const INITIAL_RSP: u64 = 0x8000;
/// Initial instruction pointer (the reset vector).
pub const INITIAL_RIP: u64 = CODE_GPA;
/// Initial RFLAGS: bit 1 is reserved and always set.
pub const INITIAL_RFLAGS: u64 = 0x0000_0000_0000_0002;

// ---------------------------------------------------------------------------
// Control-register / MSR bits for long mode entry
// ---------------------------------------------------------------------------

/// CR0.PE: protection enable.
pub const CR0_PE: u64 = 1 << 0;
/// CR0.ET: extension type (fixed on modern x86).
pub const CR0_ET: u64 = 1 << 4;
/// CR0.PG: paging enable.
pub const CR0_PG: u64 = 1 << 31;
/// CR4.PAE: physical address extension (required for long mode).
pub const CR4_PAE: u64 = 1 << 5;
/// EFER.LME: long mode enable.
pub const EFER_LME: u64 = 1 << 8;
/// EFER.LMA: long mode active.
pub const EFER_LMA: u64 = 1 << 10;

/// Initial CR0: PE | ET | PG.
pub const INITIAL_CR0: u64 = CR0_PE | CR0_ET | CR0_PG;
/// Initial CR3: PML4 base.
pub const INITIAL_CR3: u64 = PML4_GPA;
/// Initial CR4: PAE.
pub const INITIAL_CR4: u64 = CR4_PAE;
/// Initial EFER: LME | LMA.
pub const INITIAL_EFER: u64 = EFER_LME | EFER_LMA;

// ---------------------------------------------------------------------------
// Page-table entry flags
// ---------------------------------------------------------------------------

/// Page present.
pub const PTE_PRESENT: u64 = 1 << 0;
/// Page writable.
pub const PTE_WRITABLE: u64 = 1 << 1;
/// Page size: a PD entry maps a 2 MiB page.
pub const PTE_PAGE_SIZE: u64 = 1 << 7;

/// One 2 MiB page.
pub const TWO_MIB: u64 = 2 * 1024 * 1024;
/// Number of PD entries (512 × 2 MiB = 1 GiB identity map).
pub const PD_ENTRIES: usize = 512;

// ---------------------------------------------------------------------------
// GDT layout
// ---------------------------------------------------------------------------

/// Code segment selector (GDT index 1).
pub const GDT_CODE_SELECTOR: u16 = 0x08;
/// Data segment selector (GDT index 2).
pub const GDT_DATA_SELECTOR: u16 = 0x10;
/// 64-bit code segment descriptor: present, code/readable, L=1, D=0.
pub const GDT_CODE_DESCRIPTOR: u64 = 0x0020_9A00_0000_0000;
/// Data segment descriptor: present, data/writable.
pub const GDT_DATA_DESCRIPTOR: u64 = 0x0000_9200_0000_0000;
/// Number of GDT entries (null + code + data).
pub const GDT_ENTRY_COUNT: usize = 3;
/// GDT size in bytes.
pub const GDT_SIZE_BYTES: usize = GDT_ENTRY_COUNT * 8;

/// 64-bit code segment `type` field: code, readable, accessed.
pub const SEG_TYPE_CODE: u8 = 0xB;
/// Data segment `type` field: data, writable, accessed.
pub const SEG_TYPE_DATA: u8 = 0x3;

// ---------------------------------------------------------------------------
// Guest code
// ---------------------------------------------------------------------------

/// The marker guest machine code (64-bit):
///
/// ```text
/// mov  eax, 0x4B      ; B8 4B 00 00 00      marker byte into AL
/// mov  edx, 0x3F8     ; BA F8 03 00 00      serial data register into DX
/// out  dx, al         ; EE                  write AL to port 0x3F8
/// hlt                 ; F4                  stop the vCPU
/// ```
#[must_use]
pub fn guest_code() -> Vec<u8> {
    let mut code = Vec::with_capacity(12);
    code.push(0xB8); // mov eax, imm32
    code.extend_from_slice(&u32::from(GUEST_MARKER_BYTE).to_le_bytes());
    code.push(0xBA); // mov edx, imm32
    code.extend_from_slice(&u32::from(SERIAL_PORT).to_le_bytes());
    code.push(0xEE); // out dx, al
    code.push(0xF4); // hlt
    code
}

/// Writes one little-endian `u64` into the identity-mapped buffer at `gpa`.
fn put_u64(mem: &mut [u8], gpa: u64, value: u64) {
    let start = gpa as usize;
    mem[start..start + 8].copy_from_slice(&value.to_le_bytes());
}

/// Writes the guest code, the long-mode identity page tables, and the GDT into
/// an identity-mapped memory buffer (buffer index == guest physical address).
///
/// Pure and deterministic. The buffer must be at least large enough to hold the
/// GDT (`GDT_GPA + GDT_SIZE_BYTES`); the canonical 16 MiB slot is ample.
pub fn write_boot_layout(mem: &mut [u8]) {
    // Guest code at the reset vector.
    let code = guest_code();
    let code_start = CODE_GPA as usize;
    mem[code_start..code_start + code.len()].copy_from_slice(&code);

    // PML4[0] -> PDPT.
    put_u64(mem, PML4_GPA, PDPT_GPA | PTE_PRESENT | PTE_WRITABLE);
    // PDPT[0] -> PD.
    put_u64(mem, PDPT_GPA, PD_GPA | PTE_PRESENT | PTE_WRITABLE);
    // PD[0..512] -> 2 MiB identity pages.
    for i in 0..PD_ENTRIES {
        let gpa = PD_GPA + (i as u64) * 8;
        let mapped = (i as u64) * TWO_MIB;
        put_u64(
            mem,
            gpa,
            mapped | PTE_PRESENT | PTE_WRITABLE | PTE_PAGE_SIZE,
        );
    }
    // GDT: null, 64-bit code, data.
    put_u64(mem, GDT_GPA, 0);
    put_u64(mem, GDT_GPA + 8, GDT_CODE_DESCRIPTOR);
    put_u64(mem, GDT_GPA + 16, GDT_DATA_DESCRIPTOR);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MEMORY_SIZE_BYTES, SERIAL_PORT};

    fn read_u64(mem: &[u8], gpa: u64) -> u64 {
        let start = gpa as usize;
        u64::from_le_bytes(mem[start..start + 8].try_into().unwrap())
    }

    #[test]
    fn guest_code_is_the_exact_marker_program() {
        let code = guest_code();
        // mov eax,0x4B ; mov edx,0x3F8 ; out dx,al ; hlt
        assert_eq!(
            code,
            vec![0xB8, 0x4B, 0x00, 0x00, 0x00, 0xBA, 0xF8, 0x03, 0x00, 0x00, 0xEE, 0xF4]
        );
        // Ends in HLT so the vCPU loop stops cleanly.
        assert_eq!(*code.last().unwrap(), 0xF4);
    }

    #[test]
    fn guest_code_targets_the_serial_port_and_marker() {
        let code = guest_code();
        // The marker byte and the serial port are embedded little-endian.
        assert_eq!(code[1], GUEST_MARKER_BYTE);
        let port = u32::from_le_bytes([code[6], code[7], code[8], code[9]]) as u16;
        assert_eq!(port, SERIAL_PORT);
    }

    #[test]
    fn boot_layout_writes_code_page_tables_and_gdt() {
        let mut mem = vec![0u8; MEMORY_SIZE_BYTES as usize];
        write_boot_layout(&mut mem);

        // Code at GPA 0.
        assert_eq!(mem[0], 0xB8);
        assert_eq!(mem[11], 0xF4);

        // PML4[0] -> PDPT | P | W.
        assert_eq!(
            read_u64(&mem, PML4_GPA),
            PDPT_GPA | PTE_PRESENT | PTE_WRITABLE
        );
        // PDPT[0] -> PD | P | W.
        assert_eq!(
            read_u64(&mem, PDPT_GPA),
            PD_GPA | PTE_PRESENT | PTE_WRITABLE
        );
        // PD[0] maps GPA 0 as a 2 MiB page (mapped base is 0).
        assert_eq!(
            read_u64(&mem, PD_GPA),
            PTE_PRESENT | PTE_WRITABLE | PTE_PAGE_SIZE
        );
        // PD[1] maps GPA 0x200000.
        assert_eq!(
            read_u64(&mem, PD_GPA + 8),
            TWO_MIB | PTE_PRESENT | PTE_WRITABLE | PTE_PAGE_SIZE
        );
        // GDT: null, code, data.
        assert_eq!(read_u64(&mem, GDT_GPA), 0);
        assert_eq!(read_u64(&mem, GDT_GPA + 8), GDT_CODE_DESCRIPTOR);
        assert_eq!(read_u64(&mem, GDT_GPA + 16), GDT_DATA_DESCRIPTOR);
    }

    #[test]
    fn long_mode_control_bits_are_consistent() {
        // Entering long mode requires paging + PAE + LME (+ LMA for KVM_SET_SREGS).
        assert_ne!(INITIAL_CR0 & CR0_PG, 0);
        assert_ne!(INITIAL_CR0 & CR0_PE, 0);
        assert_ne!(INITIAL_CR4 & CR4_PAE, 0);
        assert_ne!(INITIAL_EFER & EFER_LME, 0);
        assert_ne!(INITIAL_EFER & EFER_LMA, 0);
        assert_eq!(INITIAL_CR3, PML4_GPA);
        assert_eq!(INITIAL_RFLAGS, 0x2);
    }

    #[test]
    fn gdt_descriptors_encode_long_mode_code() {
        // The code descriptor must have the L (long-mode) bit set and D clear.
        // Byte 6 high nibble holds flags: AVL(bit4) L(bit5) D/B(bit6) G(bit7).
        let code_flags = ((GDT_CODE_DESCRIPTOR >> 48) & 0xF0) as u8;
        let l_bit = code_flags & 0x20;
        let db_bit = code_flags & 0x40;
        assert_ne!(l_bit, 0, "code segment must be long-mode (L=1)");
        assert_eq!(db_bit, 0, "long-mode code must have D/B=0");
    }
}
