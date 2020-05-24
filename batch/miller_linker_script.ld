OUTPUT_FORMAT(pei-i386)
SECTIONS
{
  /* w32miller default linker script */
  /* Make the virtual address and file offset synced if the alignment is
     lower than the target page size. */
  . = SIZEOF_HEADERS;
  . = ALIGN(__section_alignment__);
  .text  __image_base__ + ( __section_alignment__ < 0x1000 ? . : __section_alignment__ ) : SUBALIGN(0x0)
  {
    __text_start__ = . ;
    *(.text)
    *(.text$*)
    *(.text.*)
    *(.rdata)
    *(.rdata$*)
    *(.rdata.*)

    __rt_psrelocs_start = .;
    *(.rdata_runtime_pseudo_reloc)
    __rt_psrelocs_end = .;

    __text_end__ = . ;
  }

  /*  .data BLOCK(__section_alignment__) : */
  .data . : SUBALIGN(0x0)
  {
    __data_start__ = . ;
    *(.data)
    *(.data2)
    *(.data$*)
    *(.jcr)
    *(.bss)
    *(COMMON)
    __data_end__ = . ;
  }

  __rt_psrelocs_size = __rt_psrelocs_end - __rt_psrelocs_start;
  ___RUNTIME_PSEUDO_RELOC_LIST_END__ = .;
  __RUNTIME_PSEUDO_RELOC_LIST_END__ = .;
  ___RUNTIME_PSEUDO_RELOC_LIST__ = . - __rt_psrelocs_size;
  __RUNTIME_PSEUDO_RELOC_LIST__ = . - __rt_psrelocs_size;

  /DISCARD/ :
  {
    *(.init)
    *(.etext)
    *(._etext)
    *(.debug$S)
    *(.debug$T)
    *(.debug$F)
    *(.drectve)
    *(.note.GNU-stack)
    *(.gnu.lto_*)
    *(.pdata)
    *(.eh_frame*)
    *(.crt)
    *(.CRT$XC*)  /* C initialization */
    *(.CRT$XI*)  /* C++ initialization */
    *(.CRT$XL*)  /* TLS callbacks */
    *(.CRT$XP*)  /* Pre-termination */
    *(.CRT$XT*)  /* Termination */
    *(.tls)
    *(.tls$AAA)
    *(.tls)
    *(.tls$)
    *(.tls$ZZZ)
    *(.rsrc)
    *(.rsrc$*)
    *(.stab)
    *(.stabstr)
    *(.debug_*)
    *(.zdebug_*)
  }
  .endjunk BLOCK(__section_alignment__) :
  {
    /* end is deprecated, don't use it */
    PROVIDE (end = .);
    PROVIDE ( _end = .);
     __end__ = .;
  }

  .reloc : SUBALIGN(0x0)
  {
    *(.reloc)
  }
}
