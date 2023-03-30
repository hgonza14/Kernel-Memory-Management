#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/types.h>

/*
WSS - process working set size
RSS - present process in physical memory
swap - process swapped out to disk
*/

//process ID
int pid;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jake Gonzales");

//Using module_param() macro to pass pid to kernel module 
module_param(pid, int, S_IRUSR);

//Function to first check if the given pte was accessed and clear the accessed bit of a given page table entry.
int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
	int ret = 0;
	//checks if the given pte was accessed and clears the accessed bit of this pte entry; it returns 1 if the pte was accessed
	if (pte_young(*ptep))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *)&ptep->pte);
	return ret;
}
struct hrtimer timer;

//Page table walk function
void check_page(struct vm_area_struct *vma, struct mm_struct *task_mm, unsigned long address, unsigned int** rss, unsigned int** swap, unsigned int** wss)
{
	//Linux 5-level page table pgd, p4d, pud, pmd, and pte
	//The following tables are accessed from mm_struct
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;


	/*
	A page that is present in memory is part of the process RSS. A page that is valid but not present
	in memory is in SWAP. While walking the page tables, 
	*/


	// get pgd from task_mm and the page address
	pgd = pgd_offset(task_mm, address);
	// check if pgd does not exist or if it's not in a suitable state for modification.
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		(**swap)++;
		return;
	}

	// get p4d from task_mm and the page address
	p4d = p4d_offset(pgd, address);
	// check if p4d does not exist or if it's not in a suitable state for modification.
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		(**swap)++;
		return;
	}

	// get pud from task_mm and the page address
	pud = pud_offset(p4d, address);
	// check if pud does not exist or if it's not in a suitable state for modification.
	if (pud_none(*pud) || pud_bad(*pud))
	{
		(**swap)++;
		return;
	}

	// get pmd from task_mm and the page address
	pmd = pmd_offset(pud, address);
	// check if pmd does not exist or if it's not in a suitable state for modification.
	if (pmd_none(*pmd) || pmd_bad(*pmd))
	{
		(**swap)++;
		return;
	}

	// get pte from pmd and the page address
	ptep = pte_offset_map(pmd, address);
	// check if pte does not exist
	if (!ptep)
	{
		(**swap)++;
		return;
	}
	pte = *ptep;

	//Page that is present in memory is part of the process RSS. A page that is valid but not present in memory is in SWAP
	if (pte_present(pte))
	{
		(**rss)++;
	} else {
		(**swap)++;
	}

	(**wss) += ptep_test_and_clear_young(vma, address, ptep);

}

//High-resolution timer to calculate WSS, RSS, and swap
enum hrtimer_restart callback(struct hrtimer *timer)
{
	struct task_struct *task;
	//10 second timer
	ktime_t currtime, interval;
	currtime = ktime_get();
	interval = ktime_set(0, 10e9);
	hrtimer_forward(timer, currtime, interval);

	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (task)
	{
		struct vm_area_struct *vma;
		struct mm_struct *task_mm = task->mm;
		unsigned long address;

		unsigned int rss_count = 0;
		unsigned int * prss = &rss_count;
		unsigned int **d_prss = &prss;

		unsigned int swap_count = 0;
		unsigned int * pswap = &swap_count;
		unsigned int **d_pswap = &pswap;

		unsigned int wss = 0;
		unsigned int * pwss = &wss;
		unsigned int **d_pwss = &pwss;

		if (task_mm && task_mm->mmap)
		{
			for (vma = task_mm->mmap; vma; vma = vma->vm_next)
			{
				for (address = vma->vm_start; address < vma->vm_end; address += PAGE_SIZE)
				{
					check_page(vma, task_mm, address, d_prss, d_pswap, d_pwss);
				}
			}
		}
		printk(KERN_INFO "[PID-%d] | [RSS:%lu KB] | [SWAP:%lu KB] [WSS:%lu KB] \n", pid, rss_count * (PAGE_SIZE / 1024), swap_count * (PAGE_SIZE / 1024), wss * (PAGE_SIZE / 1024));
	}
	return HRTIMER_RESTART;
}


static int __init initialize(void)
{
	ktime_t currtime = ktime_add(ktime_get(), ktime_set(0, 10e9));
	hrtimer_init(&timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	timer.function = &callback;
	hrtimer_start(&timer, currtime, HRTIMER_MODE_ABS);

	return 0;
}

//Function to remove the module 
static void __exit clean_exit(void)
{
	int ret;
	ret = hrtimer_cancel(&timer);
}

module_init(initialize);
module_exit(clean_exit);
