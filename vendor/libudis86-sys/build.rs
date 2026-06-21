extern crate cc;

fn main() {
  cc::Build::new()
    .files(&[
      "libudis86/decode.c",
      "libudis86/itab.c",
      "libudis86/syn-att.c",
      "libudis86/syn-intel.c",
      "libudis86/syn.c",
      "libudis86/udis86.c"
    ])
    .flag("-includestring.h")
    .compile("udis86");
}
