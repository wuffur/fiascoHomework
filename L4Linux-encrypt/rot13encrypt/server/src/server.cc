//Измененный файл server.cc из examples/clntsrv с добавленными кусками ds_srv.cc
// из examples/libs/l4re/c++/shared_ds/
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
#include <l4/re/namespace>
#include <l4/re/dataspace>
#include <l4/re/util/meta>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/object_registry>
#include <l4/cxx/ipc_server>
#include "shared.h"

static L4Re::Util::Registry_server<> server;



class Encryption_server : public L4::Server_object
{
private:
  static void encrypt(char **result, unsigned long *result_size, const char *plaintext,unsigned long size);
  static void decrypt(char **result, unsigned long *result_size, const char *plaintext,unsigned long size);
  static char rot13(const char c);

  //  int 

public:
  int dispatch(l4_umword_t obj, L4::Ipc::Iostream &ios);


  

};

int
Encryption_server::dispatch(l4_umword_t obj, L4::Ipc::Iostream &ios)
{
  l4_msgtag_t t;
  char *addr = 0;
  l4_umword_t dst = obj;
  L4::Opcode opcode;
  int err=0;
  L4::Cap<L4Re::Dataspace> ds;
  ios >> t; // extract the tag

  switch (t.label())
    {
    case L4::Meta::Protocol:
      // handle the meta protocol requests, implementing the
      // runtime dynamic type system for L4 objects.
      return L4::Util::handle_meta_request<My_interface>(ios);
    case Protocol::Encryption:
      ios >> opcode;
      if(opcode != Opcode::connect)
	{
	  puts("Bad start");
	  return -L4_EAGAIN;
	}
      puts("Connect recieved");
 
      //Server to client: I'm ready (SmallBuffers are in place)
      ds = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
      if (!ds.is_valid())
	{
	  printf("Could not get capability slot!\n");
	  return -1;
	}
      printf("Sending ready: %d\n", Opcode::ready);
      ios.reset();
      ios<<l4_umword_t(Opcode::ready);
      ios<<L4::Ipc::Small_buf(ds);
      err = l4_error(ios.reply_and_wait(&dst, Protocol::Encryption));
      if(err)
	{
	  printf("Error replying: %d\n",err);
	  return err;
	}
      
      //Client to server: Sending dataspace;
      l4_msgtag_t t1;
      ios>>t1;
      if(t1.label() != Protocol::Encryption)
	{
	  puts("Wrong Protocol");
	  return -L4_EBADPROTO;
	}
      ios>>opcode;
      if (!(opcode == Opcode::func_encrypt || opcode == Opcode::func_decrypt))
	{
	  puts("Bad operation");
	  return -L4_EAGAIN;
	}
      printf("Got operation: %d\n", opcode);
      char *string, *result;
      unsigned long size,result_size;
      /*
       * Attach to arbitrary region
       */
      err = L4Re::Env::env()->rm()->attach(&addr, ds->size(),
					       L4Re::Rm::Search_addr, ds);
      if (err < 0)
	{
	  printf("Error attaching data space: %s\n", l4sys_errtostr(err));
	  return err;
	}

      size = strlen(addr);
      string = new char[size];
      strncpy(string,addr,size);
      if(opcode==Opcode::func_encrypt)
	{
	  puts("Dataspace recieved. Operation: encryption");
	  puts(string);
	  encrypt(&result, &result_size, string, size);
	}
      else
	{
	  puts("Dataspace recieved. Operation: decryption");
	  decrypt(&result, &result_size, string, size);
	}
      strncpy(addr,result,result_size);
    
      /* Detach memory from our address space */
      if ((err = L4Re::Env::env()->rm()->detach(addr, &ds)))
	return err; 
      
      /* Release and return capability slot to allocator */
      L4Re::Util::cap_alloc.free(ds, L4Re::Env::env()->task().cap());

      //Server to client: Operation done
      printf("Sending done: %d\n", Opcode::done);
      ios.reset();
      ios<<l4_umword_t(Opcode::done);
      
      return 0;
    default:
      // every other protocol is not supported.
      return -L4_EBADPROTO;
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
