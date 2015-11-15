#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>

#include <linux/slab.h>

#include "spinlock.h"
#include "osprd.h"

/* The size of an OSPRD sector. */
#define SECTOR_SIZE	512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED	0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE: Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("Skeletor");

#define OSPRD_MAJOR	222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);

typedef struct pid_node *pid_node_t;
struct pid_node {
  pid_t pid;
  pid_node_t next, prev;
};

//our pid_list will double as a queue
typedef struct pid_list *pid_list_t;
struct pid_list {
  pid_node_t head;  //first
  pid_node_t tail;  //last
};

pid_list_t init_pid_list() {
  
  pid_list_t new_list = (pid_list_t) kmalloc(sizeof(struct pid_list), GFP_ATOMIC);
  new_list->head = NULL;
  new_list->tail = NULL;
  return new_list;

}

//add new pid node to list. first argument is new pid. second argument is list to add to.
//assume new pid gets put at the end of the queue
void add_pid(pid_t new_pid, pid_list_t list) {

  //first create a new node to hold the pid
  pid_node_t new_node = (pid_node_t) kmalloc(sizeof(struct pid_node), GFP_ATOMIC);
  new_node->pid = new_pid;
  new_node->next = NULL;
  new_node->prev = NULL;

  //if list is empty, initialize the head and tail to the new node. 
  if (!list->head) {
    list->head = new_node;
    list->tail = new_node;
  }
  //list is not empty
  else {
    list->tail->next = new_node;
    new_node->prev = list->tail;
    list->tail = list->tail->next;
  }
}



//return the first pid in the queue
pid_t get_first(pid_list_t list) {
  
  return list->head->pid;

}

//pop front of the queue

pid_t pop_front(pid_list_t list) {
  
  pid_t first_in_line;
  pid_node_t first_node;

  //if list is empty
  if (!list->head) {
    return 0;
  }
  //list is not empty
  //store first node in variable
  //extract pid from first node
  //update head of the list to next in line, if there is one
  //free popped node
  else {

    first_node = list->head;
    if (list->head->next != NULL) {
      list->head = list->head->next;
    }
    else {
      list->head = NULL;
      list->tail = NULL;
    }

    first_in_line = first_node->pid;
    kfree(first_node);

  }
  
  return first_in_line;

}

//returns 0 if whatever we are trying to move from the list does not exist
//returns 1 for successful removal


/* The internal representation of our device. */
typedef struct osprd_info {
	uint8_t *data;                  // The data array. Its size is
	                                // (nsectors * SECTOR_SIZE) bytes.

	osp_spinlock_t mutex;           // Mutex for synchronizing access to
					// this block device

	unsigned ticket_head;		// Currently running ticket for
					// the device lock

	unsigned ticket_tail;		// Next available ticket for
					// the device lock

	wait_queue_head_t blockq;       // Wait queue for tasks blocked on
					// the device lock

	/* HINT: You may want to add additional fields to help
	         in detecting deadlock. */

    pid_list_t read_lock_list;
    pid_t proc_with_write_lock;
    unsigned num_read_locks;
    unsigned num_write_locks;
        

	// The following elements are used internally; you don't need
	// to understand them.
	struct request_queue *queue;    // The device request queue.
	spinlock_t qlock;		// Used internally for mutual
	                                //   exclusion in the 'queue'.
	struct gendisk *gd;             // The generic disk.
} osprd_info_t;

//Removes item with given pid from read_list
//If we find a pid with the same pid in the parameter, return 1 and remove node from list
//If we fail to find the same pid, return 0
int remove_from_list (pid_t pid, pid_list_t read_list){
	
	pid_node_t curr_node = read_list->head;

	//check if read_list is empty
	if (!curr_node){
		return 0;
	}

	//if read_list is not empty, look for the pid in the read_list
	while (!curr_node){
		
		if (curr_node->pid == pid){
			//pid was found in the head
			if (curr_node == read_list->head){
				if (curr_node->next){
					curr_node->next->prev = NULL;
					curr_node->next = read_list->head;
				}
			//pid was found in the tail
			} else if (curr_node == read_list->tail){
				if (curr_node->prev){
					curr_node->prev->next = NULL;
				}
			//pid was found in the middle of the list
			} else {  
				curr_node->prev->next = curr_node->next;
				curr_node->next->prev = curr_node->prev;
			}

			//free the node
			kfree(curr_node);
			return 1;
		}

		curr_node = curr_node->next;
	}

	//was unable to find pid in list
	return 0;
}

//Helps check for deadlock
//NOTE: We will always pass in current->pid for the first parameter
//If we find that the current->pid matches something in the read list, return 1
//If we don't find a match in read_list, return 0
int is_locked (pid_t pid, pid_list_t read_list){
	
	pid_node_t curr_node = read_list->head;

	//check if list is empty
	if (!curr_node){
		return 0;
	}

	//check in read_list for deadlock pid
	while (!curr_node){
		if (curr_node->pid == pid){
			return 1;
		}

		curr_node = curr_node->next;
	}

	//if we reach here, we haven't found the pid
	return 0;
}


#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];


// Declare useful helper functions

/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
			       void (*callback)(struct file *filp,
						osprd_info_t *user_data),
			       osprd_info_t *user_data);


/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
	if (!blk_fs_request(req)) {
		end_request(req, 0);
		return;
	}

	// EXERCISE: Perform the read or write request by copying data between
	// our data array and the request's buffer.
	// Hint: The 'struct request' argument tells you what kind of request
	// this is, and which sectors are being read or written.
	// Read about 'struct request' in <linux/blkdev.h>.
	// Consider the 'req->sector', 'req->current_nr_sectors', and
	// 'req->buffer' members, and the rq_data_dir() function.

	// Your code here.
	int num_bytes = req->current_nr_sectors * SECTOR_SIZE;
	int offset = req->sector * SECTOR_SIZE;
	void *transfer = d->data + offset;

	if (rq_data_dir(req) == READ) {
	  memcpy(req->buffer, transfer, num_bytes);
	} else if (rq_data_dir(req) == WRITE) {
	  memcpy(transfer, req->buffer, num_bytes);
	}else {
	  //eprintk("Error");
	  end_request(req, 0);
	}

	end_request(req, 1);
}


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
	// Always set the O_SYNC flag. That way, we will get writes immediately
	// instead of waiting for them to get through write-back caches.
	filp->f_flags |= O_SYNC;
	return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{
	if (filp) {
		osprd_info_t *d = file2osprd(filp);
		int filp_writable = filp->f_mode & FMODE_WRITE;

		// EXERCISE: If the user closes a ramdisk file that holds
		// a lock, release the lock.  Also wake up blocked processes
		// as appropriate.

		// Your code here.

		// This line avoids compiler warnings; you may remove it.
		(void) filp_writable, (void) d;

		//check if the ramdisk file has a lock
		//if the file has a lock
		if ( (filp->f_flags & F_OSPRD_LOCKED) != 0) {
		  
		  //eprintk("Attempting to release lock\n");
		  osp_spin_lock(&d->mutex);
		  //release the lock; first check what kind of lock it was
		  if (filp_writable) {
		    
		    //unlock write lock and update osprd_info
		    //eprintk("releasing write lock\n");
		    d->num_write_locks--;
		    d->proc_with_write_lock = -1;

		  }
		  else {
		    //unlock read lock and update osprd_info
		    //eprintk("releasing read lock\n");
		    d->num_read_locks--;
		    remove_from_list(current->pid, d->read_lock_list);
		  
		  }
		  
		  filp->f_flags &= !F_OSPRD_LOCKED;
		  osp_spin_unlock(&d->mutex);
		  wake_up_all(&d->blockq);

	       
		  return 0;
		}
		
		else {
			return -EINVAL;

		}
		
	}

	else return -EINVAL;
}


/*
 * osprd_lock
 */

/*
 * osprd_ioctl(inode, filp, cmd, arg)
 *   Called to perform an ioctl on the named file.
 */
int osprd_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	osprd_info_t *d = file2osprd(filp);	// device info
	int r = 0;			// return value: initially 0

	// is file open for writing?
	int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

	// This line avoids compiler warnings; you may remove it.
	(void) filp_writable, (void) d;

	// Set 'r' to the ioctl's return value: 0 on success, negative on error
	unsigned local_ticket;
	int return_from_wait;

	if (cmd == OSPRDIOCACQUIRE) {

		// EXERCISE: Lock the ramdisk.
		//
		// If *filp is open for writing (filp_writable), then attempt
		// to write-lock the ramdisk; otherwise attempt to read-lock
		// the ramdisk.
		//
        // This lock request must block using 'd->blockq' until:
		// 1) no other process holds a write lock;
		// 2) either the request is for a read lock, or no other process
		//    holds a read lock; and
		// 3) lock requests should be serviced in order, so no process
		//    that blocked earlier is still blocked waiting for the
		//    lock.
		//
		// If a process acquires a lock, mark this fact by setting
		// 'filp->f_flags |= F_OSPRD_LOCKED'.  You also need to
		// keep track of how many read and write locks are held:
		// change the 'osprd_info_t' structure to do this.
		//
		// Also wake up processes waiting on 'd->blockq' as needed.
		//
		// If the lock request would cause a deadlock, return -EDEADLK.
		// If the lock request blocks and is awoken by a signal, then
		// return -ERESTARTSYS.
		// Otherwise, if we can grant the lock request, return 0.

		// 'd->ticket_head' and 'd->ticket_tail' should help you
		// service lock requests in order.  These implement a ticket
		// order: 'ticket_tail' is the next ticket, and 'ticket_head'
		// is the ticket currently being served.  You should set a local
		// variable to 'd->ticket_head' and increment 'd->ticket_head'.
		// Then, block at least until 'd->ticket_tail == local_ticket'.
		// (Some of these operations are in a critical section and must
		// be protected by a spinlock; which ones?)

		// Your code here (instead of the next two lines).

	  //check for deadlock in read_list, and check if we have deadlock in the same pid
	  if (is_locked(current->pid, d->read_lock_list) || current->pid == d->proc_with_write_lock){
	  	return -EDEADLK;
	  }

	  if (filp_writable) {
	    //attempt to write-lock the ramdisk
	  	    
	    //lock the mutex; we are about to modify osprd_info (the 'd' variable)
	    osp_spin_lock(&d->mutex);
	    local_ticket = d->ticket_head;
	    d->ticket_head = d->ticket_head + 1;
	    
	    //done modifying; unlock
	    osp_spin_unlock(&d->mutex);
	    
	    //block on a wait queue until we have no write or read locks and we are next in line
        //eprintk("beginning blocking for write lock | num write locks: %d num read locks: %d ticket tail: %d local ticket:%d\n", d->num_write_locks, d->num_read_locks, d->ticket_tail, local_ticket);
	    return_from_wait = wait_event_interruptible(d->blockq, d->ticket_tail == local_ticket && d->num_write_locks == 0 && d->num_read_locks == 0);
	    //eprintk("exited block for write\n");
	  
	    //check return_from_wait value
	    //if return_from_wait returned ERESTARTSYS, it was interrupted by a signal. return ERESTARTSYS.
	    if (return_from_wait == -ERESTARTSYS) {
	    	osp_spin_lock(&d->mutex);
	    	if (local_ticket == d->ticket_tail)
				d->ticket_tail++;
			else d->ticket_head--;
			osp_spin_unlock(&d->mutex);
	      	return -ERESTARTSYS;
	    }
	    else {  //condition is true; now we can acquire the lock
	      
	      //update osprd_info
	      osp_spin_lock(&d->mutex);
	      d->num_write_locks++;
	      d->ticket_tail++;
	      d->proc_with_write_lock = current->pid;
	      osp_spin_unlock(&d->mutex);
	      
	    } 
	  }
	    //READ LOCK
	  else {

	    osp_spin_lock(&d->mutex);
	    local_ticket = d->ticket_head;
	    d->ticket_head = d->ticket_head+1;
        osp_spin_unlock(&d->mutex);
        //block until no write locks are on the disk and we are next in line
        //eprintk("beginning blocking for read lock | num write locks: %d ticket tail: %d local ticket:%d\n", d->num_write_locks, d->ticket_tail, local_ticket);
        return_from_wait = wait_event_interruptible(d->blockq, d->num_write_locks == 0 && d->ticket_tail == local_ticket);
        //eprintk("exited block for read\n");
	    if (return_from_wait == -ERESTARTSYS) {
	    	osp_spin_lock(&d->mutex);
	    	if (local_ticket == d->ticket_tail)
				d->ticket_tail++;
			else d->ticket_head--;
			osp_spin_unlock(&d->mutex);
	      	return -ERESTARTSYS;
	    }  
	    else {
			//acquire the lock
			osp_spin_lock(&d->mutex);
			d->num_read_locks++;
			d->ticket_tail++;
			add_pid(current->pid, d->read_lock_list);
			osp_spin_unlock(&d->mutex);

	    }
	  }
	  
	  filp->f_flags|=F_OSPRD_LOCKED;
	  r=0;

	} else if (cmd == OSPRDIOCTRYACQUIRE) {


		//check for write locks, or if someone is attempting to write while someone is rading
		osp_spin_lock(&d->mutex);
  		if ( ( d->num_write_locks > 0 || (d->num_read_locks > 0 && filp_writable) ) ) {
  	  		osp_spin_unlock(&d->mutex);
	  		return -EBUSY;
	  	}

	  	//if we're here, we're clear to acquire lock
		//check if read or write
		if (filp_writable){
	     	
	     	d->num_write_locks++;
	      	d->proc_with_write_lock = current->pid;
	      	
		} else {   //read

			add_pid(current->pid, d->read_lock_list);
			d->num_read_locks++;
			
		}

		filp->f_flags|=F_OSPRD_LOCKED;
		osp_spin_unlock(&d->mutex);

	} else if (cmd == OSPRDIOCRELEASE) {

		// EXERCISE: Unlock the ramdisk.
		//
		// If the file hasn't locked the ramdisk, return -EINVAL.
		// Otherwise, clear the lock from filp->f_flags, wake up
		// the wait queue, perform any additional accounting steps
		// you need, and return 0.

		// Your code here (instead of the next line).
		if ( (filp->f_flags & F_OSPRD_LOCKED) != 0) {
		  
		  	//eprintk("Attempting to release lock\n");
		  	osp_spin_lock(&d->mutex);
		  	//release the lock; first check what kind of lock it was
		  	if (filp_writable) {
		    	
		    	//unlock write lock and update osprd_info
		    	//eprintk("releasing write lock\n");
		    	d->num_write_locks--;
		    	d->proc_with_write_lock = -1;
		    	
		  	}
		  	else {
		  	  	
		  	  	//unlock read lock and update osprd_info
		  	  	//eprintk("releasing read lock\n");
		    	d->num_read_locks--;
		    	remove_from_list(current->pid, d->read_lock_list);
		    	
		  	}
		  	
		  	filp->f_flags &= !F_OSPRD_LOCKED;
	
		  	osp_spin_unlock(&d->mutex);
		  	wake_up_all(&d->blockq);
		  	return 0;
	       
		}
		
		else return -EINVAL;
	} else
		r = -ENOTTY; /* unknown command */
	return r;
}


// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
	/* Initialize the wait queue. */
	init_waitqueue_head(&d->blockq);
	osp_spin_lock_init(&d->mutex);
	d->ticket_head = d->ticket_tail = 0;
	/* Add code here if you add fields to osprd_info_t. */
	//malloc queue
	d->read_lock_list = init_pid_list();
	d->num_read_locks = 0;
	d->num_write_locks = 0;
	d->proc_with_write_lock = -1;
}


/*****************************************************************************/
/*         THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE!          */
/*                                                                           */
/*****************************************************************************/

// Process a list of requests for a osprd_info_t.
// Calls osprd_process_request for each element of the queue.

static void osprd_process_request_queue(request_queue_t *q)
{
	osprd_info_t *d = (osprd_info_t *) q->queuedata;
	struct request *req;

	while ((req = elv_next_request(q)) != NULL)
		osprd_process_request(d, req);
}


// Some particularly horrible stuff to get around some Linux issues:
// the Linux block device interface doesn't let a block device find out
// which file has been closed.  We need this information.

static struct file_operations osprd_blk_fops;
static int (*blkdev_release)(struct inode *, struct file *);

static int _osprd_release(struct inode *inode, struct file *filp)
{
	if (file2osprd(filp))
		osprd_close_last(inode, filp);
	return (*blkdev_release)(inode, filp);
}

static int _osprd_open(struct inode *inode, struct file *filp)
{
	if (!osprd_blk_fops.open) {
		memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));
		blkdev_release = osprd_blk_fops.release;
		osprd_blk_fops.release = _osprd_release;
	}
	filp->f_op = &osprd_blk_fops;
	return osprd_open(inode, filp);
}


// The device operations structure.

static struct block_device_operations osprd_ops = {
	.owner = THIS_MODULE,
	.open = _osprd_open,
	// .release = osprd_release, // we must call our own release
	.ioctl = osprd_ioctl
};


// Given an open file, check whether that file corresponds to an OSP ramdisk.
// If so, return a pointer to the ramdisk's osprd_info_t.
// If not, return NULL.

static osprd_info_t *file2osprd(struct file *filp)
{
	if (filp) {
		struct inode *ino = filp->f_dentry->d_inode;
		if (ino->i_bdev
		    && ino->i_bdev->bd_disk
		    && ino->i_bdev->bd_disk->major == OSPRD_MAJOR
		    && ino->i_bdev->bd_disk->fops == &osprd_ops)
			return (osprd_info_t *) ino->i_bdev->bd_disk->private_data;
	}
	return NULL;
}


// Call the function 'callback' with data 'user_data' for each of 'task's
// open files.

static void for_each_open_file(struct task_struct *task,
		  void (*callback)(struct file *filp, osprd_info_t *user_data),
		  osprd_info_t *user_data)
{
	int fd;
	task_lock(task);
	spin_lock(&task->files->file_lock);
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
		struct files_struct *f = task->files;
#else
		struct fdtable *f = task->files->fdt;
#endif
		for (fd = 0; fd < f->max_fds; fd++)
			if (f->fd[fd])
				(*callback)(f->fd[fd], user_data);
	}
	spin_unlock(&task->files->file_lock);
	task_unlock(task);
}


// Destroy a osprd_info_t.

static void cleanup_device(osprd_info_t *d)
{
	wake_up_all(&d->blockq);
	if (d->gd) {
		del_gendisk(d->gd);
		put_disk(d->gd);
	}
	if (d->queue)
		blk_cleanup_queue(d->queue);
	if (d->data)
		vfree(d->data);
}


// Initialize a osprd_info_t.

static int setup_device(osprd_info_t *d, int which)
{
	memset(d, 0, sizeof(osprd_info_t));

	/* Get memory to store the actual block data. */
	if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
		return -1;
	memset(d->data, 0, nsectors * SECTOR_SIZE);

	/* Set up the I/O queue. */
	spin_lock_init(&d->qlock);
	if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
		return -1;
	blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
	d->queue->queuedata = d;

	/* The gendisk structure. */
	if (!(d->gd = alloc_disk(1)))
		return -1;
	d->gd->major = OSPRD_MAJOR;
	d->gd->first_minor = which;
	d->gd->fops = &osprd_ops;
	d->gd->queue = d->queue;
	d->gd->private_data = d;
	snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
	set_capacity(d->gd, nsectors);
	add_disk(d->gd);

	/* Call the setup function. */
	osprd_setup(d);

	return 0;
}

static void osprd_exit(void);


// The kernel calls this function when the module is loaded.
// It initializes the 4 osprd block devices.

static int __init osprd_init(void)
{
	int i, r;

	// shut up the compiler
	(void) for_each_open_file;
#ifndef osp_spin_lock
	(void) osp_spin_lock;
	(void) osp_spin_unlock;
#endif

	/* Register the block device name. */
	if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
		printk(KERN_WARNING "osprd: unable to get major number\n");
		return -EBUSY;
	}

	/* Initialize the device structures. */
	for (i = r = 0; i < NOSPRD; i++)
		if (setup_device(&osprds[i], i) < 0)
			r = -EINVAL;

	if (r < 0) {
		printk(KERN_EMERG "osprd: can't set up device structures\n");
		osprd_exit();
		return -EBUSY;
	} else
		return 0;
}


// The kernel calls this function to unload the osprd module.
// It destroys the osprd devices.

static void osprd_exit(void)
{
	int i;
	for (i = 0; i < NOSPRD; i++)
		cleanup_device(&osprds[i]);
	unregister_blkdev(OSPRD_MAJOR, "osprd");
}


// Tell Linux to call those functions at init and exit time.
module_init(osprd_init);
module_exit(osprd_exit);
