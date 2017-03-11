//
//  main.cpp
//  lstasks
//
//  Created by pebble8888 on 2016/08/26.
//  Copyright © 2016年 pebble8888. All rights reserved.
//

#include <getopt.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <Carbon/Carbon.h>
#include <unistd.h>

#define PROGNAME "lstasks"

#define INDENT_L1    "  "
#define INDENT_L2    "    "
#define INDENT_L3    "      "
#define INDENT_L4    "        "
#define SUMMARY_HEADER \
    "task#  BSD pid program   PSN (high) PSN (low)  #threads\n"

static const char *task_roles[] = {
    "RENICED",
    "UNSPECIFIED",
    "FOREGROUND_APPLICATION",
    "BACKGROUND_APPLICATION",
    "CONTROL_APPLICATION",
    "GRAPHICS_SERVER"
};

#define TASK_ROLES_MAX (sizeof(task_roles)/sizeof(char *))

static const char *thread_policies[] = {
    "UNKNOWN?",
    "STANDARD|EXTENDED",
    "TIME_CONSTRAINT",
    "PRECEDENCE",
};
#define THREAD_POLICIES_MAX (sizeof(thread_policies)/sizeof(char *))

static const char *thread_states[] = {
    "NONE",
    "RUNNING",
    "STOPPED",
    "WAITING",
    "UNINTERRUPTIBLE",
    "HALTED",
};
#define THREAD_STATES_MAX (sizeof(thread_states)/sizeof(char *))

#define EXIT_ON_MACH_ERROR(msg, retval) \
    if (kr != KERN_SUCCESS) { mach_error(msg ":", kr); exit((retval)); }

static const char* getprocname(pid_t pid)
{
    size_t len = sizeof(struct kinfo_proc);
    static int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    static struct kinfo_proc kp;
    name[3] = pid;
    kp.kp_proc.p_comm[0] = '\0';
    
    if (sysctl((int *)name, sizeof(name)/sizeof(*name), &kp, &len, NULL, 0))
        return "?";
    
    if (kp.kp_proc.p_comm[0] == '\0')
        return "exited?";
    
    return kp.kp_proc.p_comm;
}

void usage()
{
    printf("usage: %s [-s|-v] [-p <pid>]\n", PROGNAME);
    exit(1);
}

int noprintf(const char *format, ...)
{
    return 0;
}

int main(int argc, char *argv[]) {
    
    int i, j, summary = 0, verbose = 0;
    int (* Printf)(const char *format, ...);
    
    pid_t pid;
    
    OSStatus status;
    ProcessSerialNumber psn;
    CFStringRef nameRef;
    char name[MAXPATHLEN];
    
    kern_return_t kr;
    mach_port_t myhost;
    mach_port_t mytask;
    mach_port_t onetask = 0;
    mach_port_t p_default_set;
    mach_port_t p_default_set_control;
    
    task_array_t task_list;
    mach_msg_type_number_t task_count;
    
    task_info_data_t tinfo;
    mach_msg_type_number_t task_info_count;
    
    task_basic_info_t basic_info;
    task_events_info_t events_info;
    task_thread_times_info_t thread_times_info;
    task_absolutetime_info_t absolutetime_info;
    
    task_category_policy_data_t category_policy;
    boolean_t get_default;
    
    audit_token_t audio_token;
    security_token_t security_token;
    
    thread_array_t thread_list;
    mach_msg_type_number_t thread_count;
    
    thread_info_data_t thinfo;
    mach_msg_type_number_t thread_info_count;
    
    thread_basic_info_t basic_info_th;
    
    thread_extended_policy_data_t extended_policy;
    thread_time_constraint_policy_data_t time_constraint_policy;
    thread_precedence_policy_data_t precedence_policy;
    
    uint32_t stat_task = 0;
    uint32_t stat_proc = 0;
    uint32_t stat_cpm = 0;
    uint32_t stat_thread = 0;
    
    Printf = printf;
    
    myhost = mach_host_self();
    mytask = mach_task_self();
    
    while ((i = getopt(argc, argv, "p:sv")) != -1) {
        switch (i) {
            case 'p':
                pid = strtoul(optarg, NULL, 10);
                kr = task_for_pid(mytask, pid, &onetask);
                EXIT_ON_MACH_ERROR("task_for_pid", 1);
                break;
            case 's':
                summary = 1;
                Printf = noprintf;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                usage();
        }
    }
    
    if (summary && verbose)
        usage();
    
    argv += optind;
    argv -= optind;
    
    kr = processor_set_default(myhost, &p_default_set);
    EXIT_ON_MACH_ERROR("processor_default", 1);
    
    kr = host_processor_set_priv(myhost, p_default_set, &p_default_set_control);
    EXIT_ON_MACH_ERROR("host_processor_set_priv", 1);
    
    kr = processor_set_tasks(p_default_set_control, &task_list, &task_count);
    EXIT_ON_MACH_ERROR("processor_set_tasks", 1);
    
    if (!verbose)
        Printf(SUMMARY_HEADER);
    
    for (i = 0; i < task_count; i++){
        if (task_list[i] == mytask)
            continue;
        
        if (onetask && (task_list[i] != onetask))
            continue;
        
        pid = 0;
        status = procNotFound;
        
        stat_task++;
        
        if (verbose)
            Printf("Task #%d\n", i);
        else 
            Printf("%5d", i);
        
        kr = pid_for_task(task_list[i], &pid);
        if ((kr == KERN_SUCCESS) && (pid > 0)) {
            stat_proc++;
            
            if (verbose)
                Printf(INDENT_L1 "BSD process id (pid)  = %u (%s)\n", pid, getprocname(pid));
            else
                Printf("  %6u %-16s", pid, getprocname(pid));
        } else 
            if (verbose)
                Printf(INDENT_L1 "BSD process id (pid)  = "
                       "/* not a BSD process */\n");
            else
                Printf("  %6s %-16s", "-", "-");
        
        if (pid > 0)
            status = GetProcessForPID(pid, &psn);
        
        if (status == noErr){
            stat_cpm++;
            if (verbose) {
                status = CopyProcessName(&psn, &nameRef);
                
                CFStringGetCString(nameRef, name , MAXPATHLEN,kCFStringEncodingASCII);
                Printf(INDENT_L1 "Carbon process name = %s\n", name);
                CFRelease(nameRef);
            } else
                Printf(" %-12d%-12d", psn.highLongOfPSN, psn.lowLongOfPSN);
        } else 
            if (verbose)
                Printf(INDENT_L1 "Carbon process name = "
                       "/* not a Carbon process */\n");
            else 
                Printf(" %-12s%-12s", "-", "-");
                
        if (!verbose)
            goto do_threads;
                
        task_info_count = TASK_INFO_MAX;
        kr = task_info(task_list[i], TASK_BASIC_INFO, (task_info_t)tinfo,
                       &task_info_count);
        if (kr != KERN_SUCCESS) {
            mach_error("task_info:", kr);
            fprintf(stderr, "*** TASK_BASIC_INFO failed (task=%x)\n",
                    task_list[i]);
            continue;
        }
        basic_info = (task_basic_info_t)tinfo;
        Printf(INDENT_L2 "virtual size = %u KB\n",
              basic_info->virtual_size >> 10);
        Printf(INDENT_L2 "resident size = %u KB\n",
               basic_info->resident_size >> 10);
        if ((basic_info->policy < 0) &&
            (basic_info->policy > THREAD_POLICIES_MAX))
            basic_info->policy = 0;
        Printf(INDENT_L2 "default policy = %u (%s)\n",
               basic_info->policy, thread_policies[basic_info->policy]);
        
        Printf(INDENT_L2 "user (terminated) = %u s%u us\n",
               basic_info->user_time.seconds,
               basic_info->user_time.microseconds);
        
        Printf(INDENT_L2 "system (terminated) = %u s %u us\n",
               basic_info->system_time.seconds,
               basic_info->system_time.microseconds);
        
        task_info_count = TASK_INFO_MAX;
        kr = task_info(task_list[i], TASK_THREAD_TIMES_INFO,
                       (task_info_t)tinfo, &task_info_count);
        if (kr == KERN_SUCCESS){
            thread_times_info = (task_thread_times_info_t)tinfo;
            Printf(INDENT_L2 "user (live) = %u s %u us\n",
                  thread_times_info->user_time.seconds,
                  thread_times_info->user_time.microseconds);
            Printf(INDENT_L2 "system (live) = %u s %u us\n",
                   thread_times_info->system_time.seconds,
                   thread_times_info->system_time.microseconds);
        }
        
        task_info_count = TASK_INFO_MAX;
        kr = task_info(task_list[i], TASK_ABSOLUTETIME_INFO,
                       (task_info_t)tinfo, &task_info_count);
        if (kr == KERN_SUCCESS) {
            Printf(INDENT_L1 "Thread times (absolute)\n");
            absolutetime_info = (task_absolutetime_info_t)tinfo;
            Printf(INDENT_L2 "user (total) = %lld\n",
                  absolutetime_info->total_user);
            Printf(INDENT_L2 "system (total) = %lld\n",
                  absolutetime_info->total_system);
            Printf(INDENT_L2 "user (live) = %lld\n",
                  absolutetime_info->threads_user);
            Printf(INDENT_L2 "system (live) = %lld\n",
                  absolutetime_info->threads_system);
        }
        
        task_info_count = TASK_INFO_MAX;
        kr = task_info(task_list[i], TASK_EVENTS_INFO, (task_info_t)tinfo,
                       &task_info_count);
        if (kr == KERN_SUCCESS) {
            events_info = (task_events_info_t)tinfo;
            Printf(INDENT_L2 "page faults = %u\n",
                   events_info->faults);
            Printf(INDENT_L2 "actual pageins = %u\n",
                   events_info->pageins);
            Printf(INDENT_L2 "copy-on-write faults = %u\n",
                   events_info->cow_faults);
            Printf(INDENT_L2 "messages sent = %u\n",
                   events_info->messages_sent);
            Printf(INDENT_L2 "messages received = %u\n",
                   events_info->messages_received);
            Printf(INDENT_L2 "Mach system calls = %u\n",
                   events_info->syscalls_mach);
            Printf(INDENT_L2 "Unix system calls = %u\n",
                   events_info->syscalls_unix);
            Printf(INDENT_L2 "context switches = %u\n",
                   events_info->csw);
        }
        
        task_info_count = TASK_CATEGORY_POLICY_COUNT;
        get_default = FALSE;
        kr = task_policy_get(task_list[i], TASK_CATEGORY_POLICY,
                             (task_policy_t)&category_policy,
                             &task_info_count, &get_default);
        if (kr == KERN_SUCCESS) {
            if (get_default == FALSE) {
                if ((category_policy.role >= -1) &&
                    (category_policy.role < (TASK_ROLES_MAX -1 )))
                    Printf(INDENT_L2 "role = %s\n",
                           task_roles[category_policy.role + 1]);
            } else 
                Printf(INDENT_L2 "role = NONE\n");
        }
        
        task_info_count = TASK_AUDIT_TOKEN_COUNT;
        kr = task_info(task_list[i], TASK_AUDIT_TOKEN,
                       (task_info_t)&audio_token, &task_info_count);
        if (kr == KERN_SUCCESS) {
            int n;
            Printf(INDENT_L2 "audit token = ");
            for (n = 0; n < sizeof(audio_token)/sizeof(uint32_t); n++)
                Printf("%x ", audio_token.val[n]);
            Printf("\n");
        }
        
    do_threads:
        
        kr = task_threads(task_list[i], &thread_list, &thread_count);
        if (kr != KERN_SUCCESS) {
            mach_error("task_threads:", kr);
            fprintf(stderr, "task_threads() failed (task=%x)\n!", task_list[i]);
            continue;
        }
        
        if (thread_count > 0)
            stat_thread += thread_count;
        
        if (!verbose) {
            Printf(" %8d\n", thread_count);
            continue;
        }
        
        Printf(INDENT_L1 "Threads in this task = %u\n", thread_count);
        
        for (j = 0; j < thread_count; j++){
            thread_info_count = THREAD_INFO_MAX;
            kr = thread_info(thread_list[j], THREAD_BASIC_INFO,
                             (thread_info_t)thinfo, &thread_info_count);
            if (kr != KERN_SUCCESS){
                mach_error("task_info:", kr);
                fprintf(stderr,
                        "*** thread_info() failed (task=%x thread=%x)\n",
                        task_list[i], thread_list[j]);
                continue;
            }
            
            basic_info_th = (thread_basic_info_t)thinfo;
            Printf(INDENT_L2 "thread %u/%u (%p) in task %u (%p)\n",
                   j, thread_count - 1, thread_list[j], i, task_list[i]);
            
            Printf(INDENT_L3 "user run time - %u s %u us\n",
                   basic_info_th->user_time.seconds,
                   basic_info_th->user_time.microseconds);
            Printf(INDENT_L3 "system run time = %u s %u us\n",
                   basic_info_th->system_time.seconds,
                   basic_info_th->system_time.microseconds);
            Printf(INDENT_L3 "scaled cpu usage percentage = %u\n",
                   basic_info_th->cpu_usage);
            switch (basic_info_th->policy){
                case THREAD_EXTENDED_POLICY:
                    Printf(INDENT_L3 "main EXTENDED_POLICY\n");
                    break;
                case THREAD_TIME_CONSTRAINT_POLICY:
                    Printf(INDENT_L3,"main TIME_CONSTRAINT_POLICY\n");
                    break;
                case THREAD_PRECEDENCE_POLICY:
                    Printf(INDENT_L3,"main PRECEDENCE_POLICY\n");
                    break;
                default:
                    Printf(INDENT_L3,"main UNKNOWN\n");
                    break;
            }
            
            //switch (basic_info_th->policy){
            //    case THREAD_EXTENDED_POLICY:
            {
                get_default = FALSE;
                thread_info_count = THREAD_EXTENDED_POLICY_COUNT;
                kr = thread_policy_get(thread_list[j], THREAD_EXTENDED_POLICY,
                                       (thread_policy_t)&extended_policy,
                                       &thread_info_count, &get_default);
                if (kr != KERN_SUCCESS){
                    //break;
                    Printf("Error!\n");
                }
                Printf(INDENT_L3 "scheduling policy = %s\n",
                       (extended_policy.timeshare == TRUE) ? \
                       "STANDARD(timeshare)" : "EXTENDED(not timeshare)");
            }
            //        break;
            //    case THREAD_TIME_CONSTRAINT_POLICY:
            {
                get_default = FALSE;
                thread_info_count = THREAD_TIME_CONSTRAINT_POLICY_COUNT;
                kr = thread_policy_get(thread_list[j],
                                       THREAD_TIME_CONSTRAINT_POLICY,
                                       (thread_policy_t)&time_constraint_policy,
                                       &thread_info_count, &get_default);
                if (kr != KERN_SUCCESS){
                    //break;
                    Printf("Error!\n");
                }
                Printf(INDENT_L3 "scheduling policy = " \
                       "TIME_CONSTRAINT\n");
                Printf(INDENT_L4 "period = %-4u\n",
                       time_constraint_policy.period);
                Printf(INDENT_L4 "computation = %-4u\n",
                       time_constraint_policy.computation);
                Printf(INDENT_L4 "constraint = %-4u\n",
                       time_constraint_policy.constraint);
                Printf(INDENT_L4 "preemptible = %s\n",
                       (time_constraint_policy.preemptible == TRUE) ? \
                       "TRUE" : "FALSE");
            }
            //        break;
            //    case THREAD_PRECEDENCE_POLICY:
            {
                get_default = FALSE;
                thread_info_count = THREAD_PRECEDENCE_POLICY;
                kr = thread_policy_get(thread_list[j], THREAD_PRECEDENCE_POLICY,
                                       (thread_policy_t)&precedence_policy,
                                       &thread_info_count, &get_default);
                
                if (kr != KERN_SUCCESS) {
                    //break;
                    Printf("Error!\n");
                }
                
                Printf(INDENT_L3 "sacheduling policy = PRECEDENCE\n");
                Printf(INDENT_L4 "importance = %-4d\n",
                       precedence_policy.importance);
            //        break;
            }
                
            //    default:
            //        Printf(INDENT_L3 "scheduling policy = UNKNOWN?\n");
            //        break;
            //}
            
            Printf(INDENT_L3
                   "run state = %-4u (%s)\n",
                   basic_info_th->run_state,
                    (basic_info_th->run_state >= THREAD_STATES_MAX) ? \
                    "?" : thread_states[basic_info_th->run_state]);
                   
                  Printf(INDENT_L3
                         "flags = %-4x%s",
                         basic_info_th->flags,
                         (basic_info_th->flags & TH_FLAGS_IDLE) ? \
                         " (IDLE)\n" : "\n");
            
            Printf(INDENT_L3 "suspend count = %u\n",
                   basic_info_th->suspend_count);
            Printf(INDENT_L3 "sleeping for time = %u s\n",
                   basic_info_th->sleep_time);
        }
        
        vm_deallocate(mytask, (vm_address_t)thread_list,
                      thread_count * sizeof(thread_act_t));
    }
    
    Printf("\n");
    
    fprintf(stdout, "%4d Mach task\n%4d Mach threads\n"
            "%4d BAS processes\n%4d CFM processes\n",
            stat_task, stat_thread, stat_proc, stat_cpm);
    
    vm_deallocate(mytask, (vm_address_t)task_list, task_count * sizeof(task_t));
    
    exit(0);
}
