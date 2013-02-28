/*
 * (c) 2008-2009 Adam Lackorzynski <adam@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */

#pragma once


#include <l4/sys/capability>
#include <l4/re/dataspace>
#include <l4/cxx/ipc_stream>
#include <stdio.h>
#include <string.h>



namespace Opcode {
enum Opcodes {
  connect,
  ready,
  done,
  func_encrypt,
  func_decrypt
};
};

namespace Protocol {
enum Protocols {
  Encryption
};
};


/**
 * Interface class for remote object.
 *
 * Inherits vrom L4::Kobject, via the L4::Kobject_t helper
 * template that generates the dynamic type information for the meta
 * protocol.
 */

static int free_mem(void *virt_addr)
{
  int r;
  L4::Cap<L4Re::Dataspace> ds;

  /* Detach memory from our address space */
  if ((r = L4Re::Env::env()->rm()->detach(virt_addr, &ds)))
    return r;

  /* Free memory at our memory allocator, this is optional */
  if ((r = L4Re::Env::env()->mem_alloc()->free(ds)))
    return r;

  /* Release and return capability slot to allocator */
  L4Re::Util::cap_alloc.free(ds, L4Re::Env::env()->task().cap());

  /* All went ok */
  return 0;
}

static int get_ds_and_addr(L4::Cap<L4Re::Dataspace> *ds, char** addr, unsigned long size)
{
  // get capacity
  *ds = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
  if (!(*ds).is_valid())
    {
      printf("Dataspace allocation failed.\n");
      return -1;
    }
  
  //get memory
  int r =  L4Re::Env::env()->mem_alloc()->alloc(size, *ds, 0);
  if (r < 0)
    {
      printf("mem_alloc->alloc() failed.\n");
      L4Re::Util::cap_alloc.free(*ds);
      return r;
    }
  
  //attach memory
  r =  L4Re::Env::env()->rm()->attach(addr, (*ds)->size(),
					L4Re::Rm::Search_addr,
					*ds);
  if (r < 0)
    {
      printf("Error attaching data space: %s\n", l4sys_errtostr(r));
      L4Re::Util::cap_alloc.free(*ds);
      return r;
    }

  /*OK*/
  return 0;

}

class My_interface : public L4::Kobject_t<My_interface, L4::Kobject>
{
  // Disable instantiation and copy, because we just qork via
  // L4::Cap<...> references.
  L4_KOBJECT(My_interface)
    
private:
  int ask_text_processing(L4::Opcode code,
			   const char *text,
			   unsigned long size,
			   char **result,
			   unsigned long *result_size);
public:
  int encrypt(const char *text,
	      unsigned long size,
	      char **result,
	      unsigned long *result_size);

  int decrypt(const char *text,
	      unsigned long size,
	      char **result,
	      unsigned long *result_size);
};


//Since we need client to share memory with server and not vice versa
// and there is no method in server_object for preparation before dispatch
// (where we could insert SmallBuffers into the stream)
// I couldn't find another way and implemented this innecessary complex 'talk'
// between client and server.

int My_interface::ask_text_processing(L4::Opcode code,
				      const char *text,
				      unsigned long size,
				      char **result,
				      unsigned long *result_size)
{
  l4_msgtag_t t;
  L4::Ipc::Iostream s(l4_utcb());
  L4::Opcode opcode;

 //Client to server: get ready to accepting capabilities.
  s<<l4_umword_t(Opcode::connect); 
  int r = l4_error(s.call(cap(), Protocol::Encryption));
  if (r)
    return r;


  //Server to client: I'm ready (SmallBuffers are in place)
  s>>t;
  if(t.label() != Protocol::Encryption)
    {
      puts("Error: Wrong protocol.");
      return -1;
    }
  s>>opcode;
  if(opcode != Opcode::ready)
    {
      puts("Error. Server is not ready");
      return -1;
    }
  puts("Server is ready");
  
  //Client to server: Sending dataspace;
  char* addr;

  //get and attach dataspace
  L4::Cap<L4Re::Dataspace> ds;
  r = get_ds_and_addr(&ds,&addr,size);
  if(r)
    return r;
  strncpy(addr, text, size);

  s.reset();
  s<<l4_umword_t(code);
  s<<ds;
  r = l4_error(s.call(cap(), Protocol::Encryption)); 
  if (r)
    return r;
      
  //Server to client: Operation done
  s>>t;
  if(t.label() != Protocol::Encryption)
    {
      puts("Error: Wrong protocol.");
      return -L4_EBADPROTO;
    }
  s>>opcode;
  if(opcode != Opcode::done)
    {
      puts("Error.");
      return -1;
    }
  
  *result_size = strlen(addr);
  *result = new char[*result_size];
  strncpy(*result, addr, *result_size);

  // free memory,
  r = free_mem(addr);
  
  if(r)
    return r;
  return 0;
  
}
 
int My_interface::encrypt(const char *text,
			  unsigned long size,
			  char **result,
			  unsigned long *result_size)
{
  return ask_text_processing(Opcode::func_encrypt, text, size, result, result_size);
}

int My_interface::decrypt(const char *text,
			  unsigned long size,
			  char **result,
			  unsigned long *result_size)
{
  return ask_text_processing(Opcode::func_decrypt, text, size, result, result_size);
}
  
  
  
  





