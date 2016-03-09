#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <debug.h>
#include <user/syscall.h>
#include "threads/vaddr.h"
#include "threads/synch.h"

/* Contributor-added libraries and macros */
#define EXE_MAGIC 0x08048000
#define GET_FILE struct file * file_ = thread_get_file (thread_current(), fd); \
                          if (file_ == NULL) return

static void syscall_handler (struct intr_frame *);
struct lock file_lock;

/* Copy SIZE bytes from usrc (user address) to the kernel / pagedir.
   If usrc is out of range or is not a user virtual address, then exit(-1) */
unsigned
copy_in (const void * usrc)
{
  void * ptr;
  if ((const void*) usrc < EXE_MAGIC || !is_user_vaddr ((const void*) usrc))
  {
    exit(-1);
  }
  ptr = pagedir_get_page (thread_current ()->pagedir, usrc);
  if(ptr == NULL)
  {
    exit(-1);
  }
  return (unsigned) ptr;
}

/* Terminates Pintos by calling shutdown_power_off() */
void
halt ()
{
    shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. If the 
   process's parent waits for it (see below), this is the status that will be 
   returned. Conventionally, a status of 0 indicates success and nonzero values 
   indicate errors. */
void 
exit (int status)
{
  /* Gets the current user program */
  struct thread * current = thread_current();
  /* Check if there is a parent thread for the current program. If so,
     get the current thread's parent and set the status to exit. */
  struct thread * parent = current->parent;
  if (parent != NULL)
  {
    struct child_elem * c = current->childelem;
    c->rc = status;
    c->status[3] = true;
  }
  /* Status is returned as a stdout */
  printf("%s: exit(%d)\n", current->name, status);
  thread_exit();
}

/* Runs the executable whose name is given in cmd_line, passing any given 
   arguments, and returns the new process's program id (pid). Must return 
   pid -1, which otherwise should not be a valid pid, if the program cannot 
   load or run for any reason. */
pid_t
exec (const char * cmd_line)
{
  pid_t pid = process_execute (cmd_line);
  
  /* Store the parent thread and get it's child */
  struct thread * parent = thread_current ();
  struct child_elem * c = child_get_element (&parent->child_list, pid);
  
  /* Check if the child loaded, and yield the thread until it gets called
     as thread_ready() */
  if (c->status[1] == false)
    thread_yield();
  
  /* Check if loading child failed.
     If load failed, return from exec with error code, else return the PID
     of the child that's not working */
  if (c->status[2])
    return -1;
  else
    return pid;
}

/* Waits for a child process pid and retrieves the child's exit status.
   If pid is still alive, waits until it terminates. Then, returns the status 
   that pid passed to exit. If pid did not call exit(), but was terminated by 
   the kernel (e.g. killed due to an exception), wait(pid) must return -1. */
int 
wait (pid_t pid)
{
  int status;
  struct child_elem * c = child_get_element (&thread_current ()->child_list, 
                                             pid);
  if (c == NULL)
    return -1;
  /* If the child has an exit status */
  else if (c->status[3])
  {
    status = c->rc;
    list_remove (&c->elem);
    free (c);
    return status;
  }
  /* If the child has a waiting status or if the tid is not valid 
     (terminated by the kernel) */
  else if (c->status[0] || !tid_valid (pid))
    return -1;
  /* Get the current thread and set its status to wait */
  struct thread * cur = thread_current();
  c->status[0] = true;

  while (!c->status[3] && tid_valid (pid))
    thread_yield();
  c->status[0] = false;
  /* Remove the child element from the list and deallocate the child elem */
  status = c->rc;
  list_remove (&c->elem);
  free (c);

  return status;  
}

/* Creates a new file called file initially initial_size bytes in size. 
   Returns true if successful, false otherwise. */
bool 
create (const char * file, unsigned initial_size)
{
  lock_acquire (&file_lock);
  bool rc = filesys_create (file, initial_size);
  lock_release (&file_lock);
  return rc;
}

/* Deletes the file called file. Returns true if successful, false otherwise. 
   A file may be removed regardless of whether it is open or closed, and 
   removing an open file does not close it. */
bool 
remove (const char* file)
{
  lock_acquire (&file_lock);
  bool rc = filesys_remove (file);
  lock_release (&file_lock);
  return rc;
}

/* Opens the file called file. Returns a nonnegative integer handle called a 
   "file descriptor" (fd), or -1 if the file could not be opened.
   File descriptors numbered 0 and 1 are reserved for the console: 
       fd 0 (STDIN_FILENO) is standard input, 
       fd 1 (STDOUT_FILENO) is standard output. */
int 
open (const char * file)
{
  int fd;
  struct file * file_;
  
  lock_acquire (&file_lock);
  file_ = filesys_open (file);
  lock_release (&file_lock);
  
  /* If the file could not be opened */
  if(file_ != NULL)
  {
    struct thread * parent = thread_current();
    struct file_elem * file_elem;
    
    file_elem = (struct file_elem*)malloc (sizeof (struct file_elem));
    file_elem->file_ptr = file_;
    file_elem->fd = parent->fd;
    
    parent->fd += 1;
    parent->num_files += 1;
    
    list_push_back (&parent->file_list, &file_elem->elem);
    return file_elem->fd;
  }
  else
    return -1;
}

/* Returns the size, in bytes, of the file open as fd. */
int 
filesize (int fd)
{
  struct file * file = thread_get_file (thread_current(), fd);
  if(file == NULL)
    return -1;
      
  lock_acquire (&file_lock);
  int rc = file_length (file);
  lock_release (&file_lock);

  return rc;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number 
   of bytes actually read (0 at end of file), or -1 if the file could not be 
   read (due to a condition other than end of file). Fd 0 reads from the 
   keyboard using input_getc(). */
int 
read (int fd, void *buffer, unsigned size)
{
  /* If fd == 0 at end of file, return bytes read.
     Else get the current thread and read file_read */
  if (fd == 0)
  { 
    unsigned i = 0;
    uint8_t * buf_temp = (uint8_t*) buffer;
    while (i < size)
      buf_temp[i++] = input_getc();
    return size;
  }
  else
  {
    lock_acquire (&file_lock);
    struct file * file_ = thread_get_file (thread_current(), fd);
    if (file_ == NULL)
    {
      lock_release (&file_lock);
      return -1;
    }
    int rc = file_read (file_, buffer, size);
    lock_release (&file_lock);
    return rc;
  }
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
   bytes actually written, which may be less than size if some bytes could 
   not be written. */
int 
write (int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    putbuf (buffer, size);
    return size;
  }
  GET_FILE -1;
  lock_acquire (&file_lock);
  int rc = file_write (file_, buffer, size);
  lock_release (&file_lock);
  return rc;
}

/* Changes the next byte to be read or written in open file fd to position, 
   expressed in bytes from the beginning of the file. (Thus, a position of 0 
   is the file's start.)
       A seek past the current end of a file is not an error. 
       A later read obtains 0 bytes, indicating end of file. */
void 
seek (int fd, unsigned position)
{
  GET_FILE;
  file_seek (file_, position);
}

/* Returns the position of the next byte to be read or written in open file fd, 
   expressed in bytes from the beginning of the file. */
unsigned 
tell (int fd)
{
  GET_FILE -1;
  return file_tell (file_);
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly 
   closes all its open file descriptors, as if by calling this function for 
   each one. */
void 
close (int fd)
{
  GET_FILE;
  lock_acquire (&file_lock);
  file_close (file_);
  lock_release (&file_lock);
  
  /* Close all open file descriptors */
  struct list l = thread_current ()->file_list;
  
  struct list_elem *e;
  struct file_elem *f;
  for (e = list_begin (&l); e != list_end (&l); e = list_next (e))
  {
    f = list_entry (e, struct file_elem, elem);
    if (f->fd == fd)
    {
      list_remove (e);
      free(f);
      break;
    }
  }
  thread_current ()->num_files--;
}

void 
set_arg (struct intr_frame * f, unsigned * argv, int n)
{
  unsigned i;
  unsigned * ptr;
  for (i = 0; i < n; i++)
  {
    ptr = (unsigned *) f->esp + i + 1;
    if (!is_user_vaddr ((const void *) ptr) || (const void *) ptr < EXE_MAGIC)
    {
      exit(-1);
    }
    argv[i] = *((unsigned*) f->esp + i + 1);
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  unsigned arg[3];
  
  if (!is_user_vaddr ((const void*) f->esp) || 
      (const void*) f->esp < EXE_MAGIC)
    {
      exit(-1);
    }
    
	/* ##Get syscall number
	     copy_in (&callNum, f->esp, sizeof callNum);
	     
	   ##Using the number find out which system call is being used
	     numOfArgs = number of args that system call uses {0,1,2,3}
	     copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * numOfArgs);
	     
	   ##Use switch statement or something and run this below for each
	   ##Depending on the callNum...
	     f->eax = desired_sys_call_fun (args[0], args[1], args[2]); */
    
  switch (*(unsigned *) f->esp)
  {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_EXIT:
    {
      set_arg(f,arg,1);
      exit(arg[0]);
      break;
    }
    case SYS_EXEC:
    {
      set_arg(f,arg,1);
      arg[0] = copy_in((const void*) arg[0]);
      f->eax = exec((const char*)arg[0]);
      break;
    }
    case SYS_WAIT:
        {
            set_arg(f,arg,1);
            f -> eax = wait(arg[0]);
            break;
        }
    case SYS_CREATE:
        {
            set_arg(f,arg,2);
            arg[0] = copy_in((const void*) arg[0]);
            f->eax = create((const char*)arg[0], arg[1]);
            break;
        }
    case SYS_REMOVE:
        {
           set_arg(f,arg,1);
           arg[0] = copy_in((const void*) arg[0]);
           f->eax = remove((const char*)arg[0]);
            break;
        }
    case SYS_OPEN:
        {
           set_arg(f,arg,1);
           arg[0] = copy_in((const void*) arg[0]);
           f->eax = open((const char*)arg[0]);
            break;
        }
    case SYS_FILESIZE:
        {
            set_arg(f,arg,1);
            f->eax = filesize(arg[0]);
            break;
        }
    case SYS_READ:
        {
            set_arg(f,arg,3);
            arg[1] = copy_in((const void*) arg[1]);
            f->eax = read(arg[0],(const void*)arg[1],arg[2]);
            break;
        }
    case SYS_WRITE:
        {
            set_arg(f,arg,3);
            arg[1] = copy_in((const void*) arg[1]);
            f->eax = write(arg[0],(const void*)arg[1],arg[2]);
            break;
        }
    case SYS_SEEK:
        {
            set_arg(f,arg,2);
            seek(arg[0],arg[1]);
            break;
        }
    case SYS_TELL:
        {
            set_arg(f,arg,1);
            f->eax = tell(arg[0]);
            break;
        }
    case SYS_CLOSE:
        {
            set_arg(f,arg,1);
            close(arg[0]);
            break;
        }
  }
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  ks = palloc_get_page (0);
  if (ks == NULL) 
    thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
       
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

