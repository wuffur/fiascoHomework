#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <l4/re/c/mem_alloc.h>
#include <l4/re/c/rm.h>
#include <l4/re/c/util/cap_alloc.h>
#include <l4/re/c/dataspace.h>
#include <l4/sys/err.h>
#include <l4/re/env.h>
#include <l4/sys/ipc.h>
#include <l4/rot13encrypt/sharedc.h>

MODULE_LICENSE("GPL");

static dev_t number;
static struct cdev c_dev;
static char* addr;
static char* result;
static l4re_ds_t ds;
static l4re_env_t* env;
static l4_cap_idx_t server; 
static char* string = NULL;
static size_t  size = 0;
static size_t result_size;

static int encrypt_open(struct inode *i, struct file *f)
{
  if((f->f_flags & O_ACCMODE)==O_WRONLY)
    {
      size = 0;
      kfree(string);
    }
  return 0;
}

static int encrypt_close(struct inode *i, struct file *f)
{
  l4_msg_regs_t *mr;
  l4_msgtag_t tag,ret;
  int err;
  if((f->f_flags & O_ACCMODE)==O_WRONLY)
    {
      mr = l4_utcb_mr();
      mr->mr[0] = (l4_umword_t)ENCRYPT_CONNECT;
      tag = l4_msgtag(ENCRYPT_PROTO, 1 ,0,0);

      l4_ipc_call(server, l4_utcb(), tag, L4_IPC_NEVER);
      if(mr->mr[0] != ENCRYPT_READY)
	{
	  return -1;
	}
      
      //Get memory
      if ((err=l4re_ma_alloc(size, ds, 0)))
	return err;
      
      //Attach memory
      if ((err = l4re_rm_attach((void**)&addr, size, L4RE_RM_SEARCH_ADDR, ds, 0, L4_PAGESHIFT)))
	return err;
      
      memcpy(addr, string, size);
      mr->mr[0] = ENCRYPT_ENCRYPT;
      mr->mr[1] = L4_ITEM_MAP | ((l4_umword_t)L4_MAP_ITEM_MAP);
      mr->mr[2] = l4_obj_fpage(ds,0,L4_FPAGE_RWX).raw;
      tag = l4_msgtag(ENCRYPT_PROTO, 1, 1, 0);

      ret = l4_ipc_call(server, l4_utcb(), tag, L4_IPC_NEVER);
      if(mr->mr[0] != ENCRYPT_DONE)
	{
	  err = mr->mr[0];
	  return -1;
	}
      
      memcpy(string, addr, size);
      result = string;
      result_size = size;
      size = 0;
      string = NULL;
      
      //Detach memory
      if ((err = l4re_rm_detach_ds(addr, &ds)))
	return err;
      
      //Free memory
      if ((err = l4re_ma_free(ds)))
	return err;
      
    }
  return 0;
}

static ssize_t encrypt_read(struct file *f, char __user *buf, size_t
		       len, loff_t *off)
{
  size_t count;
  if(*off >= result_size)
    return 0;
  if(*off + len > result_size)
    count = result_size - *off;
  else
    count = len;
  
  if(copy_to_user(buf, result+*off, count))
    return -EFAULT;
  
  *off += count;
  return count;
}

static ssize_t encrypt_write(struct file *f, const char __user *buf,
			size_t len, loff_t *off)
{
  char* swap = string;
  if (size + len == 0)
    return 0;
  string = (char*)kmalloc(size + len, GFP_KERNEL);
  if(string==NULL)
    {
      string = swap;
      return -ENOMEM;
    }
  memcpy(string, swap, size);
  if(copy_from_user(string+size, buf, len))
    {
      kfree(string);
      string = swap;
      return -EFAULT;
    }
  size += len;
  kfree(swap);
  return len;
}

static struct file_operations encrypt_fops =
  {
    .owner = THIS_MODULE,
    .open = encrypt_open,
    .release = encrypt_close,
    .read = encrypt_read,
    .write = encrypt_write
  };


static int __init encrypt_init(void)
{
  printk(KERN_INFO "L4Encrypt registered\n");
  if (alloc_chrdev_region(&number, 0, 1,"L4ROT13Encrypt"))
    {
      return -1;
    }
  printk(KERN_INFO "L4Encrypt: Chardev allocated major: %d, minor %d\n", 
	 MAJOR(number), MINOR(number));


  cdev_init(&c_dev, &encrypt_fops);
  if (cdev_add(&c_dev, number, 1) == -1)
    {
      unregister_chrdev_region(number, 1);
      return -1;
    }
  printk(KERN_INFO "L4Encrypt: Device initiated\n");
  /* Getting dataspace capability */
  ds = l4re_util_cap_alloc();
  if(l4_is_invalid_cap(ds))
    { 
      cdev_del(&c_dev);
      unregister_chrdev_region(number,1);
      return -1;
    }
  printk(KERN_INFO "L4Encrypt: Dataspace capability obtained\n");
  /* Getting server capability*/
  server = l4re_env_get_cap("crypt_server");
  if(l4_is_invalid_cap(server))
    {
      l4re_util_cap_free(ds);
      cdev_del(&c_dev);
      unregister_chrdev_region(number,1);
      return -1;
    }
  env = l4re_env();
  printk(KERN_INFO "L4Encrypt: Server capability obtained\n");
  

  return 0;
  
  
}

static void __exit encrypt_exit(void)
{
      l4re_util_cap_free(ds);
      cdev_del(&c_dev);
      unregister_chrdev_region(number,1);
}

module_init(encrypt_init);
module_exit(encrypt_exit);
