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
int exec (const char *cmd_line);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

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
	int cur_fd = t->fd;
	struct file *f = filesys_open(file);
	if(f == NULL){
		return -1;
	} 
	else{
		for(int i = 3; i < MAX_FD; i++){
			if (t->fd_table[i] == NULL) {
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
    
    if (fd == 1 || fd == 2 || fd >= MAX_FD) {
        exit(-1);
    }
	
	if(fd < 0 || fd >= MAX_FD){
		exit(-1);
	}
	struct file *f = t->fd_table[fd];
	if(f == NULL){
		exit(-1);
	}
	return file_read(f, buffer, size);
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
/*
	현재의 프로세스가 cmd_line에서 이름이 주어지는 실행가능한 프로세스로 변경됩니다.
	이때 주어진 인자들을 전달합니다. 성공적으로 진행된다면 어떤 것도 반환하지 않습니다. 
	만약 프로그램이 이 프로세스를 로드하지 못하거나 다른 이유로 돌리지 못하게 되면 exit state -1을 반환하며 프로세스가 종료됩니다. 
	이 함수는 exec 함수를 호출한 쓰레드의 이름은 바꾸지 않습니다. file descriptor는 exec 함수 호출 시에 열린 상태로 있다는 것을 알아두세요
*/
int exec (const char *file){
	char* temp = 
	process_exec(file);
}

/*

THREAD_NAME이라는 이름을 가진 현재 프로세스의 복제본인 새 프로세스를 만듭니다.
피호출자(callee) 저장 레지스터인 %RBX, %RSP, %RBP와 %R12 - %R15를 제외한 레지스터 값을 복제할 필요가 없습니다. 
자식 프로세스의 pid를 반환해야 합니다. 그렇지 않으면 유효한 pid가 아닐 수 있습니다. 자식 프로세스에서 반환 값은 0이어야 합니다. 
자식 프로세스에는 파일 식별자 및 가상 메모리 공간을 포함한 복제된 리소스가 있어야 합니다. 
부모 프로세스는 자식 프로세스가 성공적으로 복제되었는지 여부를 알 때까지 fork에서 반환해서는 안 됩니다. 
즉, 자식 프로세스가 리소스를 복제하지 못하면 부모의 fork() 호출이 TID_ERROR를 반환할 것입니다.
템플릿은 `threads/mmu.c`의 `pml4_for_each`를 사용하여 해당되는 페이지 테이블 구조를 포함한 전체 사용자 메모리 공간을 복사하지만, 
전달된 `pte_for_each_func`의 누락된 부분을 채워야 합니다.

*/
// pid_t fork (const char *thread_name){
	
// }

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
	// case SYS_FORK:
	// 	f->R.rax = fork(f->R.rdi);
	// 	break;
	default:
		exit(-1);
	}
	// printf ("system call!\n");
	// thread_exit ();
}