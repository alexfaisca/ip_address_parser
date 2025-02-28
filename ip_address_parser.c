#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

#define ERROR_OK 0
#define ERROR_INVALID_ARGUMENTS 1
#define ERROR_MEMORY 2
#define ERROR_UNKNOWN 3

#define IPV4_SIZE 4
#define IPV6_SIZE 16


int secure_free_byte_array(uint8_t **array, uint32_t size) {
  // secure free -> zero out structure
  for (uint32_t i = 0; i < size; (*array)[i++] = 0);
  free(*array);
  *array = NULL;
  return ERROR_OK;
}


int parse_ipv4_address(const char *ip_address, uint8_t **parsed_address) {
  int32_t aux;
  int16_t i = 0;

  if (!ip_address || !parsed_address)
    return ERROR_INVALID_ARGUMENTS;

  aux = strlen(ip_address);
  if (aux < 7 || aux > 15 || strspn(ip_address, "0123456789.") != aux)
    return ERROR_INVALID_ARGUMENTS;

  *parsed_address = malloc(IPV4_SIZE * sizeof(uint8_t));
  if(!(*parsed_address))
    return ERROR_MEMORY;

  for (char *s = ip_address, *e = ip_address;; e++) {
    if (i == IPV4_SIZE) {
      secure_free_byte_array(parsed_address, IPV4_SIZE);
      return ERROR_INVALID_ARGUMENTS;
    }

    if (*e == '.') {
      *e = '\0';

      aux = strlen(s);
      if (aux == 0 || aux > 3) {
        *e = '.';
        secure_free_byte_array(parsed_address, IPV4_SIZE);
        return ERROR_INVALID_ARGUMENTS;
      }

      aux = (int) strtoul(s, NULL, 10);
      if (aux < 0 || aux > 255) {
        *e = '.';
        secure_free_byte_array(parsed_address, IPV4_SIZE);
        return ERROR_INVALID_ARGUMENTS;
      }

      (*parsed_address)[i++] = (uint8_t) aux;

      *e = '.';
      s = e + 1;
    } else if (*e == '\0') {
      aux = strlen(s);
      if (aux == 0 || aux > 3) {
        secure_free_byte_array(parsed_address, IPV4_SIZE);
        return ERROR_INVALID_ARGUMENTS;
      }

      aux = (int) strtoul(s, NULL, 10);
      if (aux < 0 || aux > 255) {
        secure_free_byte_array(parsed_address, IPV4_SIZE);
        return ERROR_INVALID_ARGUMENTS;
      }

      (*parsed_address)[i++] = (uint8_t) aux;
      break;
    }
  }

  if (i != IPV4_SIZE) { // guarantees there were IPV4_SIZE numbers
    secure_free_byte_array(parsed_address, IPV4_SIZE);
    return ERROR_INVALID_ARGUMENTS;
  }

  return ERROR_OK;
}


int parse_ipv6_address(char *ip_address, uint8_t **parsed_address) {
  int32_t aux;
  int16_t i = 0, ipv4 = 0, ellipsed = 0;
  char *ipv4_segment = NULL;

  if (!ip_address || !parsed_address)
    return ERROR_INVALID_ARGUMENTS;

  aux = strlen(ip_address);
  if (aux < 2 || aux > 45) // accounting for max length ipv4 compatible / mapped
    return ERROR_INVALID_ARGUMENTS;
  if (strspn(ip_address, "0123456789abcdefABCDEF:") != aux) {
    if (strspn(ip_address, "0123456789abcdefABCDEF:.") == aux) {
      for (char *s = ip_address; s[i] != '\0'; s[i] == '.' ? i++ : s++);
      if (i > 3) {
        return ERROR_INVALID_ARGUMENTS;
      }
      i = 0;
      ipv4 = 1;
    } else {
      return ERROR_INVALID_ARGUMENTS;
    }
  }

  *parsed_address = malloc(IPV6_SIZE * sizeof(uint8_t));
  if (!(*parsed_address)) {
    return ERROR_MEMORY;
  }

  for (char *s = ip_address, *e = ip_address;; e++) {
    if (i >= IPV6_SIZE - IPV4_SIZE) {
      if (i == IPV6_SIZE) {
        secure_free_byte_array(parsed_address, IPV6_SIZE);
        return ERROR_INVALID_ARGUMENTS;
      } else if(ipv4) {
        ipv4_segment = s;
        break;
      }
    }

    if (*e == ':') {

      *e = '\0';
      aux = strlen(s);

      if (aux > 0) {

        if (aux > 4) {
          *e = ':';
          secure_free_byte_array(parsed_address, IPV6_SIZE);
          return ERROR_INVALID_ARGUMENTS;
        }

        aux = (int) strtoul(s, NULL, 16);
        *e = ':';

        if (aux < 0 || aux > 65535) {
          secure_free_byte_array(parsed_address, IPV6_SIZE);
          return ERROR_INVALID_ARGUMENTS;
        }

        (*parsed_address)[i++] = (uint8_t) ((int)aux >> 8);
        (*parsed_address)[i++] = (uint8_t) ((int)aux % 256);

      } else {

        *e = ':';

        if (*(e + 1) == ':') {
          if (s == ip_address) {
            s = ++e + 1;
          } else { // third ':' in a row, invalid syntax
            secure_free_byte_array(parsed_address, IPV6_SIZE);
            return ERROR_INVALID_ARGUMENTS;
          }
        }

        if (ellipsed) {
          secure_free_byte_array(parsed_address, IPV6_SIZE);
          return ERROR_INVALID_ARGUMENTS;
        }

        (*parsed_address)[i++] = (uint8_t) 0;
        (*parsed_address)[i++] = (uint8_t) 0;
        ellipsed = i;

      }

      s = e + 1;

    } else if (*e == '.') { // mapped / wrapped ellipsed ipv4 address

      ipv4_segment = s;
      break;

    } else if (*e == '\0') {

      aux = strlen(s);

      if (aux > 0) {
        if (aux > 4) {
          secure_free_byte_array(parsed_address, IPV6_SIZE);
          return ERROR_INVALID_ARGUMENTS;
        }

        aux = (int) strtoul(s, NULL, 16);

        if (aux < 0 || aux > 65535) {
          secure_free_byte_array(parsed_address, IPV6_SIZE);
          return ERROR_INVALID_ARGUMENTS;
        }

        (*parsed_address)[i++] = (uint8_t) ((int)aux >> 8);
        (*parsed_address)[i++] = (uint8_t) ((int)aux % 256);

      } else {
        if (ellipsed) {
          secure_free_byte_array(parsed_address, IPV6_SIZE);
          return ERROR_INVALID_ARGUMENTS;
        }

        for (; i < IPV6_SIZE;)
          (*parsed_address)[i++] = (uint8_t) 0;
      }

      break;

    }
  }

  if (ipv4) {
    uint8_t *ipv4_address = NULL;
    if ((aux = parse_ipv4_address(ipv4_segment, &ipv4_address)) != ERROR_OK) {
      secure_free_byte_array(parsed_address, IPV6_SIZE);
      return aux;
    }

    for(uint8_t j = 0; j < IPV4_SIZE; j++)
      (*parsed_address)[i + j] = (uint8_t) ipv4_address[j];

    secure_free_byte_array(&ipv4_address, IPV4_SIZE);
    i +=4;
  }

  if (ellipsed && i != IPV6_SIZE) {
    for (uint8_t j = IPV6_SIZE - 1; j > IPV6_SIZE - 1 - (i - ellipsed); j--)
      (*parsed_address)[j] = (*parsed_address)[i - (IPV6_SIZE - j)];
 
    for (uint8_t j = 0; j < IPV6_SIZE - i; j++)
      (*parsed_address)[ellipsed + j] = 0;
  }

  return ERROR_OK;
}


int main(int argc, char *argv[]) {

  if (argc < 2) {
    return ERROR_INVALID_ARGUMENTS;
  }

  int16_t error;
  uint8_t *address = NULL;

  error = parse_ipv4_address(argv[1], &address);

  if (error != ERROR_OK) {

    printf("not ipv4\n");

  } else {

    for (int i = 0; i < IPV4_SIZE; i++)
      printf("%d\n", address[i]);

    secure_free_byte_array(&address, IPV4_SIZE);

  }

  error = parse_ipv6_address(argv[1], &address);

  if (error != ERROR_OK) {

    printf("not ipv6\n");

  } else {

    for (int i = 0; i < IPV6_SIZE; i++)
      printf("%d\n", address[i]);

    secure_free_byte_array(&address, IPV6_SIZE);

  }

  return ERROR_OK;
}


