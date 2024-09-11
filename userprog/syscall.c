#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void check_addr(void *addr){
	struct thread *t = thread_current();

	if(!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL){
		exit(-1);
	}
}
/* The main system call interface */
void halt(){
	power_off();
}

void exit(int status){
	thread_current()->exit_stauts = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

bool create (const char *file, unsigned initial_size){
	check_addr(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file){
	check_addr(file);
	return filesys_remove(file);
}

int open (const char *file){
	check_addr(file);
	struct thread* t = thread_current();
	if(!filesys_open(file) || t->fd >= MAX_FD){
		return -1;
	} 
	else{
		t->fd_table[t->fd] = file;
		return t->fd++;
	}
}

void close (int fd){
	struct thread* t = thread_current();
	if(fd < 0 || fd >= MAX_FD){
		exit(-1);
	}
	struct file *f = t->fd_table[fd];
	if(f == NULL){
		exit(-1);
	}
	file_close(f);
	t->fd_table[fd] = NULL;
}

int write (int fd, const void *buffer, unsigned size){
	if(fd == STDOUT_FILENO)
		putbuf(buffer, size);
	return size;
}

void
syscall_handler (struct intr_frame *f UNUSED) {
	
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi,f->R.rsi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
	default:
		exit(-1);
	}
	// printf ("system call!\n");
	// thread_exit ();
}