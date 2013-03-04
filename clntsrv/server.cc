//Измененный файл server.cc из examples/clntsrv
/*
 * (c) 2008-2009 Adam Lackorzynski <adam@os.inf.tu-dresden.de>,
 *               Alexander Warg <warg@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#include <stdio.h>
#include <l4/re/env>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/object_registry>
#include <l4/cxx/ipc_server>
#include <l4/cxx/ipc_stream> //Для буферовcc
#include "shared.h"

static L4Re::Util::Registry_server<> server;



class Encryption_server : public L4::Server_object
{
public:
  int dispatch(l4_umword_t obj, L4::Ipc::Iostream &ios);
  static void encrypt(char **result, unsigned long *result_size, const char *plaintext,unsigned long size);
  static void decrypt(char **result, unsigned long *result_size, const char *plaintext,unsigned long size);
  static char rot13(const char c);

  

};

int
Encryption_server::dispatch(l4_umword_t, L4::Ipc::Iostream &ios)
{
  l4_msgtag_t t;
  ios >> t;

  if (t.label() != Protocol::Encryption)
    return -L4_EBADPROTO;

  L4::Opcode opcode;
  ios >> opcode;
  
  char *string=0;
  char *result=0;
  unsigned long string_size=0;
  unsigned long result_size=0;
  switch (opcode)
    {
    case Opcode::func_encrypt:
      string_size = MAX_MSG_SIZE;
      string = new char[string_size];
      ios>>L4::Ipc::buf_cp_in(string, string_size);
      encrypt(&result, &result_size, string, string_size);
      ios << L4::Ipc::buf_cp_out(result,result_size);
      delete [] string;
      delete [] result;
      return L4_EOK;
    case Opcode::func_decrypt:
      string_size = MAX_MSG_SIZE;
      string = new char[string_size];
      ios>>L4::Ipc::buf_cp_in(string, string_size);
      decrypt(&result, &result_size, string, string_size);
      ios << L4::Ipc::buf_cp_out(result,result_size);
      delete [] string;
      delete [] result;
      return L4_EOK;
    default:
      return -L4_ENOSYS;
    }
}

void Encryption_server::encrypt(char **result, unsigned long *result_size, const char *plaintext,unsigned long size)
{
  *result_size = size;
  *result = new char[*result_size];
  for(unsigned long i =0; i<size;i++)
    {
      (*result)[i] = rot13(plaintext[i]);
    }
}

void Encryption_server::decrypt(char **result, unsigned long *result_size, const char *plaintext,unsigned long size)
{
  *result_size = size;
  *result = new char[*result_size];
  for(unsigned long i =0; i<size;i++)
    {
      (*result)[i] = rot13(plaintext[i]);
    }
}


char Encryption_server::rot13(const char c)
{
  if (c>='a' && c<='z')
    return ((c-'a') + 13)%26 + 'a';
  else if(c>='A' && c<='Z')
    return ((c -'A') + 13)%26 + 'A';
  else 
    return c;
}


int
main()
{
  static Encryption_server calc;

  // Register encryption server
  if (!server.registry()->register_obj(&calc, "crypt_server").is_valid())
    {
      printf("Could not register my service, is there a 'crypt_server' in the caps table?\n");
      return 1;
    }

  server.loop();

  return 0;
}
