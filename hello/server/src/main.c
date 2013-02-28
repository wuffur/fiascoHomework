/*
 * (c) 2008-2009 Adam Lackorzynski <adam@os.inf.tu-dresden.de>,
 *               Frank Mehnert <fm3@os.inf.tu-dresden.de>,
 *               Lukas Grützmacher <lg2@os.inf.tu-dresden.de>
 *     economic rights: Technische Universität Dresden (Germany)
 *
 * This file is part of TUD:OS and distributed under the terms of the
 * GNU General Public License 2.
 * Please see the COPYING-GPL-2 file for details.
 */
#include <l4/re/env.h>
#include <l4/sys/ipc.h>
#include <l4/sys/vcon.h>

int
main(void)
{
  l4re_env_t *env = l4re_env();
  l4_msg_regs_t *mr = l4_utcb_mr();
  
  mr->mr[0] = L4_VCON_WRITE_OP;
  mr->mr[1] = 14;
  memcpy(&mr->mr[2], "Hello World!\n", 14);

  l4_msgtag_t tag,ret;
  tag = l4_msgtag(L4_PROTO_LOG, 6,
		  0, 0);
  for (;;)
    {
      ret=l4_ipc_send(env->log, l4_utcb(), tag, L4_IPC_NEVER);
      sleep(1);
    }
}
