use libc;
use types::{ud, ud_operand};
use itab::ud_mnemonic_code;

extern "C" {
    /// Initializes an instance.
    pub fn ud_init(ud: *mut ud);

    /// Sets the mode of disassembly. Possible values are 16, 32, and 64. By
    /// default, the library works in 32bit mode.
    pub fn ud_set_mode(ud: *mut ud, mode: u8);

    /// Sets the program counter (IP/EIP/RIP). This changes the offset of the
    /// assembly output generated, with direct effect on branch instructions.
    pub fn ud_set_pc(ud: *mut ud, program_counter: u64);

    /// Sets a pointer to a function, to callback for input. The callback is
    /// invoked each time libudis86 needs the next byte in the input stream. To
    /// single end-of-input, this callback must return the constant UD_EOI.
    pub fn ud_set_input_hook(ud: *mut ud, callback: ::std::option::Option<unsafe extern "C" fn(ud: *mut ud) -> libc::c_int>);

    /// Sets the input source for the library to a buffer of size bytes.
    pub fn ud_set_input_buffer(ud: *mut ud, data: *const u8, len: usize);

    /// Sets the input source to a file pointed to by a given standard library
    /// FILE pointer. Note that libudis86 does not perform any checks, and
    /// assumes that the file pointer is properly initialized and open for
    /// reading.
    pub fn ud_set_input_file(ud: *mut ud, file: *mut libc::FILE);

    /// Sets the vendor of whose instruction to choose from. This is only useful
    /// for selecting the VMX or SVM instruction sets at which point INTEL and
    /// AMD have diverged significantly. At a later stage, support for a more
    /// granular selection of instruction sets maybe added.
    ///
    /// - UD_VENDOR_INTEL - for INTEL instruction set.
    /// - UD_VENDOR_ATT - for AMD instruction set.
    /// - UD_VENDOR_ANY - for any valid instruction in either INTEL or AMD.
    pub fn ud_set_vendor(ud: *mut ud, vendor: libc::c_uint);

    /// Sets the function that translates the intermediate decode information to
    /// a human readable form. There are two inbuilt translators,
    ///
    /// - `ud_translate_intel` for INTEL (NASM-like) syntax.
    /// - `ud_translate_att` for AT&T (GAS-like) syntax.
    ///
    /// If you do not want libudis86 to translate, you can pass NULL to the
    /// function, with no more translations thereafter. This is useful when you
    /// only want to identify chunks of code and then create the assembly output
    /// if needed, or when you are only interested in examining the instructions
    /// and do not want to waste cycles generating the assembly language output.
    ///
    /// If you want to create your own translator, you can specify a pointer to
    /// your own function. This function must accept a single parameter, the
    /// udis86 object ud_t, and it will be invoked everytime an instruction is
    /// decoded.
    pub fn ud_set_syntax(ud: *mut ud, translator: ::std::option::Option<unsafe extern "C" fn(arg1: *mut ud)>);

    /// Skips ahead n number of bytes in the input stream.
    pub fn ud_input_skip(ud: *mut ud, skipn: usize);

    /// Test for end of input. You can use this function to test if udis86 has
    /// exhausted the input.
    pub fn ud_input_end(ud: *const ud) -> libc::c_int;

    /// Returns the number of bytes decoded.
    pub fn ud_decode(ud: *mut ud) -> libc::c_uint;

    /// Disassembles the next instruction in the input stream.
    /// Returns the number of bytes disassembled. A 0 indicates end of input.
    /// Note, to restart disassembly after the end of input, you must call one
    /// of the input setting functions with a new source of input.
    ///
    /// A common use-case pattern for this function is in a loop:
    ///
    /// ```norun
    /// while ud_disassemble(&mut object) > 0 {
    ///   // Use or print decode info.
    /// }
    /// ```
    pub fn ud_disassemble(ud: *mut ud) -> libc::c_uint;

    /// Translator for the Intel syntax.
    pub fn ud_translate_intel(ud: *mut ud);

    /// Translator for the AT&T syntax.
    pub fn ud_translate_att(ud: *mut ud);

    /// If the syntax is specified, returns pointer to the character string
    /// holding assembly language representation of the disassembled
    /// instruction.
    pub fn ud_insn_asm(ud: *const ud) -> *const libc::c_char;

    /// Returns pointer to the buffer holding the instruction bytes. Use
    /// `ud_insn_len` to determine the size of this buffer.
    pub fn ud_insn_ptr(ud: *const ud) -> *const u8;

    /// Returns the offset of the disassembled instruction in terms of the
    /// program counter value specified initially.
    pub fn ud_insn_off(ud: *const ud) -> u64;

    /// Returns pointer to a character string holding the hexadecimal
    /// representation of the disassembled bytes.
    pub fn ud_insn_hex(ud: *mut ud) -> *const libc::c_char;

    /// Returns the number of bytes disassembled.
    pub fn ud_insn_len(ud: *const ud) -> libc::c_uint;

    /// Returns a reference (`ud_operand`) to the nth (starting with 0) operand
    /// of the instruction. If the instruction does not have such an operand,
    /// the function returns `null`.
    pub fn ud_insn_opr(ud: *const ud, n: libc::c_uint) -> *const ud_operand;

    /// Returns true if the operand uses a segment register.
    pub fn ud_opr_is_sreg(opr: *const ud_operand) -> libc::c_int;

    /// Returns true if the operand uses a general purpose register.
    pub fn ud_opr_is_gpr(opr: *const ud_operand) -> libc::c_int;

    /// Returns the instruction mnemonic in the form of an enumerated constant
    /// (`ud_mnemonic_code`). As a convention all mnemonic constants are
    /// composed by prefixing standard instruction mnemonics with `UD_I`. For
    /// example, the enumerations for mov, xor and jmp are `UD_Imov`, `UD_Ixor`,
    /// and `UD_Ijmp`, respectively.
    pub fn ud_insn_mnemonic(ud: *const ud) -> ud_mnemonic_code;

    /// Returns a pointer to a character string corresponding to the given
    /// mnemonic code. Returns a `null` if the code is invalid.
    pub fn ud_lookup_mnemonic(code: ud_mnemonic_code) -> *const libc::c_char;

    /// Associates a pointer with the udis86 object to be retrieved and used in
    /// client functions, such as the input hook callback function.
    pub fn ud_set_user_opaque_data(ud: *mut ud, data: *mut libc::c_void);

    /// Returns any pointer associated with the udis86 object, using the
    /// `ud_set_user_opaque_data` function.
    pub fn ud_get_user_opaque_data(ud: *const ud) -> *mut libc::c_void;

    /// Sets a custom assembler output buffer.
    pub fn ud_set_asm_buffer(ud: *mut ud, data: *mut libc::c_char, len: usize);

    /// Sets a symbol resolver for relative targets used in the translation
    /// phase.
    ///
    /// The resolver is a function that takes a `u64` address and returns a
    /// symbolic name for the that address. The function also takes a second
    /// argument pointing to an integer that the client can optionally set to a
    /// non-zero value for offsetted targets. (symbol + offset) The function may
    /// also return `null`, in which case the translator only prints the target
    /// address.
    ///
    /// The function pointer maybe `null` which resets symbol resolution.
    pub fn ud_set_sym_resolver(ud: *mut ud, resolver: ::std::option::Option<unsafe extern "C" fn(ud: *mut ud, addr: u64, offset: *mut i64) -> *const libc::c_char>);
}
