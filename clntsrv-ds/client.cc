//Переделанный client.cc из examples/clntsrv


/*
 * (c) 2008-2009 Adam Lackorzynski <adam@os.inf.tu-dresden.de>,
 *               Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#include <l4/sys/err.h>
#include <l4/sys/types.h>
#include <l4/re/env>
#include <l4/re/util/cap_alloc>
#include <l4/cxx/ipc_stream>

#include <stdio.h>
#include <string.h>

#include "shared.h"



int
main()
{
  
  L4::Cap<My_interface> server = L4Re::Env::env()->get_cap<My_interface>("crypt_server");
  if (!server.is_valid())
    {
      printf("Could not get server capability!\n");
      return 1;
    }
  char* result = 0;
  unsigned long size = 0;

  puts("Encrypting \"Hello World!\" in ROT13:");
  if (server->encrypt("Hello World!\n", 14, &result, &size))
    {
      puts("Error talking to server");
      return -1;
    }
  puts("Cipher:");
  printf("%s\n", result);
  delete [] result;
  
  puts("Decrypting \"Hello World!!\" in ROT13:");
  if (server->decrypt("Hello World!!\n", 15, &result, &size))
    {
      puts("Error talking to server");
      return -1;
    }
  puts("Plaintext:");
  puts(result);
  delete [] result;
  
  return 0;
}
