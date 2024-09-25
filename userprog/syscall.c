#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "string.h"
#include "userprog/process.h"
#include "threads/palloc.h"

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


void halt (void);
void exit (int status);
int exec (const char *file);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int fork (const char *thread_name, struct intr_frame* f);
int wait(int pid);

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
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

bool create (const char *file, unsigned initial_size){
	check_addr(file);
	if(file[0] == "\0" || file == NULL || strlen(file) > 16 || initial_size < 0) return 0;
	return filesys_create(file, initial_size);
}

bool remove(const char *file){
	check_addr(file);
	return filesys_remove(file);
}

int open (const char *file){
	check_addr(file);

	struct thread* t = thread_current();
	int cur_fd;
	struct file *f = filesys_open(file);
	if(f == NULL){
		return -1;
	} 
	else{
		for(int i = 3; i < MAX_FD; i++){
			if (t->fd_table[i] == NULL) {// talbe의 null값이 경우에 해당 인덱스를 fd로 줌 null이 없다면?
				cur_fd = i;
				break;
			}
		}
	}
	t->fd_table[cur_fd] = f;
	return cur_fd;
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

	return;
}

int write (int fd, const void *buffer, unsigned size){
	check_addr(buffer);
	if(fd < 1 || fd >= MAX_FD) exit(-1);
	struct thread *t = thread_current();
	struct file *f = t->fd_table[fd];
	if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
		return size;
	}
	else{
		return file_write(f, buffer, size);
	}
}

int read (int fd, void *buffer, unsigned size){
	check_addr(buffer);
	struct thread* t = thread_current();
	if (fd == 0) {
        unsigned i;
        for (i = 0; i < size; i++) {
            ((char *)buffer)[i] = input_getc();  // 키보드로부터 입력
        }
        return size;
    }
    if (fd < 0 || fd == 1 || fd == 2 || fd >= MAX_FD) {
        exit(-1);
    }

	struct file *f = t->fd_table[fd];
	if(f == NULL){
		exit(-1);
	}
	int file_count = file_read(f, buffer, size);
	return file_count;
}

void seek(int fd, unsigned position){
	struct thread *t = thread_current();
	struct file *f = t->fd_table[fd];
	file_seek(f, position);
}

unsigned tell(int fd){
	struct thread *t = thread_current();
	struct file *f = t->fd_table[fd];
	file_tell(f);
}

int filesize(int fd){
	struct thread *t = thread_current();
	struct file *f = t->fd_table[fd];
	return file_length(f);
}

int exec (const char *file){
	check_addr(file);
	char *fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        exit(-1);    
    strlcpy(fn_copy, file, PGSIZE);
	if(process_exec(fn_copy) == -1) exit(-1);
}

int fork (const char *thread_name, struct intr_frame* f){
	return process_fork(thread_name, f);
}

int wait(int pid){
	return process_wait(pid);
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
		break;
	case SYS_SEEK:
		seek(f->R.rdi,f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	default:
		exit(-1);
	}
	// printf ("system call!\n");
	// thread_exit ();
}