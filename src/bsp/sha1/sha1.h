#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stddef.h>

int sha1digest(uint8_t *digest, char *hexdigest, const uint8_t *data, size_t databytes);

#endif // SHA1_H
