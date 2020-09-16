#include <ber-tlv.h>

#include <stdio.h>

int main(int argc, char *argv[])
{
    uint8_t tlvObject[] = {0xE1, 0x0B, 0xC1, 0x03, 0x01, 0x02,
                           0x03, 0xC2, 0x00, 0xC3, 0x02, 0xAA,
                           0xBB};

    print_ber_tlv(tlvObject, sizeof(tlvObject) / sizeof(tlvObject[0]));

    return 0;
}
