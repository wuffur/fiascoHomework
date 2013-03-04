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


static int
encrypt_call(L4::Cap<void> const &server, char **result, unsigned long* result_size,
              const char *plaintext, unsigned long size)
{
  if (size > MAX_MSG_SIZE)
    {
      puts("Error. The plaintext is too long")
	return -1;
    }
  L4::Ipc::Iostream s(l4_utcb());
  s << l4_umword_t(Opcode::func_encrypt) << L4::Ipc::buf_cp_out(plaintext,size);
  int r = l4_error(s.call(server.cap(), Protocol::Encryption));
  if (r)
    return r; // failure
  *result = new char[MAX_MSG_SIZE];
  *result_size = MAX_MSG_SIZE;
  s >> L4::Ipc::buf_cp_in(*result, *result_size);
  return 0; // ok
}

static int
decrypt_call(L4::Cap<void> const &server, char **result, unsigned long* result_size,
              const char *plaintext, unsigned long size)
{
  if (size > MAX_MSG_SIZE)
    {
      puts("Error. The cipher is too long")
	return -1;
    }
  L4::Ipc::Iostream s(l4_utcb());
  s << l4_umword_t(Opcode::func_decrypt) << L4::Ipc::buf_cp_out(plaintext,size);
  int r = l4_error(s.call(server.cap(), Protocol::Encryption));
  if (r)
    return r; // failure
  *result = new char[MAX_MSG_SIZE];
  *result_size = MAX_MSG_SIZE;
  s >> L4::Ipc::buf_cp_in(*result, *result_size);
  return 0; // ok
}

int
main()
{
  L4::Cap<void> server = L4Re::Env::env()->get_cap<void>("crypt_server");
  if (!server.is_valid())
    {
      printf("Could not get server capability!\n");
      return 1;
    }
  char* result = 0;
  unsigned long size = 0;

  /*По какой-то причине он отказывается передавать массив символов при первом вызове функции(любой из
   *двух - они в данном примере идентичны). Замена but_cp_in на but_in в сервере результата не дала.
   *Поиск в документации и примерах тоже не помог.
  */
  puts("Encrypting \"Hello World!\" in ROT13:");
  if (encrypt_call(server, &result, &size, "Hello World!\n", 14))
    {
      puts("Error talking to server");
      return 1;
    }
  puts("Cipher:");
  printf("%s\n", result);
  delete [] result;

  puts("Encrypting \"Hello World!\" in ROT13:");
  if (encrypt_call(server, &result, &size, "Hello World!\n", 14))
    {
      puts("Error talking to server");
      return 1;
    }
  puts("Cipher:");
  printf("%s\n", result);
  delete [] result;
  
  puts("Decrypting \"Hello World!!\" in ROT13:");
  if (decrypt_call(server, &result, &size, "Hello World!!\n", 15))
    {
      puts("Error talking to server");
      return 1;
    }
  puts("Plaintext:");
  puts(result);
  delete [] result;
  
  return 0;
}
