SECTIONS
{
    .text :
    {
        *( .text$A );
        *( .text );
        *( .text$B );
        *( .rdata* );
        *( .text$C );
    }

    /DISCARD/ :
    {
        *(.pdata);
        *(.xdata);
        *(.debug*);
        *(.eh_frame);
        *(.note*);
        *(.comment*);
        *(.idata*);
        *(.data*);
        *(.bss*);
        *(.CRT*);
        *(.tls*);
        *(.rsrc*);
        *(.reloc*);
    }
}
