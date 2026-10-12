/* Minimal SPI1 shim for the TTU-3 board support package. */
#ifndef SPI_H
#define SPI_H

#include <stdint.h>

void    spi_select(void);
void    spi_deselect(void);
uint8_t spi_transfer(uint8_t out);

#endif /* SPI_H */
