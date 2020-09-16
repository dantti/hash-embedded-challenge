#include "ber-tlv.h"

#include <stdio.h>
#include <stdint.h>

#define CLASS_PRIVATE 0xC0
#define CLASS_APPLICATION 0x40
#define CLASS_CONTEXT_SPECIFIC 0x80
#define CLASS_CONSTRUCTED 0x20
#define HAS_NEXT_BYTE 0x80

void loop_ber_tlv(uint8_t *tlvObject, int *length, int ident);

void ident_output(int ident)
{
    for (int i = 0; i < ident; ++i) {
        printf("  ");
    }
}

int decode_tag(uint8_t *tlvObject, int *length, int ident)
{
    int ret = -1;
    // First byte - tag type
    uint8_t tag = *tlvObject;
    if (*length <= 1) {
        printf("--ERROR: end of data");
        return ret;
    }

    ident_output(ident);
    if (tag & CLASS_PRIVATE) {
        printf("TAG - %#X (private class, ", tag);
    } else if (tag & CLASS_APPLICATION) {
        printf("TAG - %#X (application class, ", tag);
    } else if (tag & CLASS_CONTEXT_SPECIFIC) {
        printf("TAG - %#X (context-specific class, ", tag);
    } else {
        printf("TAG - %#X (universal class, ", tag);
    }

    if (tag & CLASS_CONSTRUCTED) {
        printf("constructed)\n");
    } else {
        printf("primitive)\n");
    }

    if ((tag & 0x1F) == 0x1F) {
        // Consume remaining TAG data
        do {
            ++tlvObject;
            --*length;
            tag = *tlvObject;
        } while (tag & 0x80);
    }

    // Next byte - tag length
    ++tlvObject;
    --*length;

    uint8_t size = *tlvObject;
    if (size == 0x80) {
        // Error
        return -1;
    }

    if (size & HAS_NEXT_BYTE) {
        int octetosTamanho = size & 0x7F;

        uint32_t ret = 0;
        for (int i = 0; i < octetosTamanho; ++i) {
            size = ret << 8 | *tlvObject;
            ++*tlvObject;
             --*length;
        }
    } else {
        ret = *tlvObject & 0x1F;
    }

    ident_output(ident);
    printf("LEN - %d bytes\n", ret);

    // Data part
    ++tlvObject;
    --*length;
    if (tag & CLASS_CONSTRUCTED) {
        // Constructed classes are like sub items so iterate again
        printf("\n");
        loop_ber_tlv(tlvObject, length, ++ident);
    } else if (ret) {
        // Primitive - just print out the data
        ident_output(ident);
        printf("VAL -");
        for (int i = 0; i < ret && i < *length; ++i) {
            printf(" %#X", *tlvObject);
            ++tlvObject;
        }
        printf("\n\n");
    } else {
        printf("\n");
    }

    *length -= ret;

    return ret + 2;
}

void loop_ber_tlv(uint8_t *tlvObject, int *length, int ident)
{
    while (*length > 1) {
        const int data_length = decode_tag(tlvObject, length, ident);

        tlvObject += data_length;
    }
}

void print_ber_tlv(uint8_t *tlvObject, int length)
{
    loop_ber_tlv(tlvObject, &length, 0);
}
