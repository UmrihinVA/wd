#define _GNU_SOURCE /* execvpe() and UNIX98 pseudoterminals */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/file.h>

#define WATCHDOG_BASEDIR "/tmp/watchdog"
#define ARGV_FIFO WATCHDOG_BASEDIR"/argv_fifo"
#define NTFY_FIFO WATCHDOG_BASEDIR"/ntfy_fifo"
#define RESP_FIFO WATCHDOG_BASEDIR"/resp_fifo"
#define DBG_FILENAME WATCHDOG_BASEDIR"/dbg"
#define RESTART_DELAY_SEC 5
#define dbg_exit char txt[100]; sprintf(txt, "line%d, errno%d\n", __LINE__, errno); write(dbg_fd, txt, strlen(txt)); abort();

struct task_info {
	struct itimerspec ts;
	struct task_info *next;
	struct task_info *prev;
	char *arg_str;
	char **argv;
	char **envp;
	int arg_str_len;
	int argv_cnt;
	int envp_cnt;
	int timerfd;
	int cmd;
	int pid;
};

enum cmd_type {
	CMD_START,
	CMD_EXIT,
	CMD_NOP,
	CMD_COUNT
};

static int dbg_fd, ntfy_fd, resp_fd, argv_fd;
static struct task_info task_info_head;
static struct task_info *head;

static void help_msg()
{
	printf("Usage: watchdog start CMD\n");
	printf("       watchdog exit  PID\n");
	printf("For stop and continue use kill -SIGNUM PID\n");
	fflush(NULL);
}

static void daemon_sigchild_handler(int sig)
{
	struct task_info *entry;
	int status, ret, pid;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1) {
			break;
		}

		/* find entry with corresponding pid */
		for (entry = head->next; (entry->pid != pid) && (entry != head); entry = entry->next) {
			continue;
		}

		/* if there is no entry with required pid, then the process was killed by a daemon */
		if (entry == head) {
			break;
		}

		/* task completed successfully */
		if (WIFEXITED(status)) {
			entry->cmd = CMD_EXIT;
		}

		/* if the task ended with a signal, then restart it with a timer */
		if (WIFSIGNALED(status)) {
			entry->ts.it_value.tv_sec = RESTART_DELAY_SEC;

			ret = timerfd_settime(entry->timerfd, 0, &entry->ts, NULL);
			if (ret == -1) {
				dbg_exit
			}

			entry->cmd = CMD_START;
		}
	}
}

/* makes fork(), return 0 if child (daemon process), 1 if parent */
static int become_daemon()
{
	int maxfd, fd, ret;

	ret = fork();
	if (ret == -1) {
		dbg_exit
	}

	if (ret != 0) {
		return 1;
	}

	ret = setsid();
	if (ret == -1) {
		dbg_exit
	}

	ret = fork();
	if (ret == -1) {
		dbg_exit
	}

	if (ret != 0) {
		_exit(EXIT_SUCCESS);
	}

	umask(0);

	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd == -1) {
		maxfd = 8192;

		for (fd = 0; fd < maxfd; fd++) {
			ret = close(fd);
			if (ret != 0) {
				dbg_exit
			}
		}
	}

	ret = close(STDIN_FILENO);
	if (ret != 0) {
		dbg_exit
	}

	fd = open("/dev/null", O_RDWR);
	if (fd != STDIN_FILENO) {
		dbg_exit
	}

	fd = dup2(STDIN_FILENO, STDOUT_FILENO);
	if (fd != STDOUT_FILENO) {
		dbg_exit
	}

	fd = dup2(STDIN_FILENO, STDERR_FILENO);
	if (fd != STDERR_FILENO) {
		dbg_exit
	}

	return 0;
}

static void daemon_setup()
{
	int ret, dummy_fd;
	struct sigaction sa;

	ret = mkdir(WATCHDOG_BASEDIR, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP);
	if (ret == -1) {
		dbg_exit
	}

	ret = mkfifo(NTFY_FIFO, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret == -1) {
		dbg_exit
	}

	ret = mkfifo(RESP_FIFO, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret == -1) {
		dbg_exit
	}

	ret = mkfifo(ARGV_FIFO, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret == -1) {
		dbg_exit
	}

	ntfy_fd = open(NTFY_FIFO, O_RDONLY | O_NONBLOCK);
	if (ntfy_fd == -1) {
		dbg_exit
	}

	resp_fd = open(RESP_FIFO, O_WRONLY);
	if (resp_fd == -1) {
		dbg_exit
	}

	argv_fd = open(ARGV_FIFO, O_RDONLY);
	if (argv_fd == -1) {
		dbg_exit
	}

	dummy_fd = open(NTFY_FIFO, O_WRONLY);
	if (dummy_fd == -1) {
		dbg_exit
	}

	dummy_fd = open(ARGV_FIFO, O_WRONLY);
	if (dummy_fd == -1) {
		dbg_exit
	}

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; /* watchdog use signal handler so EINTR may happen */
	sa.sa_handler = daemon_sigchild_handler;

	ret = sigaction(SIGCHLD, &sa, NULL);
	if (ret == -1) {
		dbg_exit
	}

	head = &task_info_head;
	memset(head, 0, sizeof(struct task_info));
	head->next = head;
	head->prev = head;

	dbg_fd = open(DBG_FILENAME, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR| S_IRGRP | S_IWGRP);
	if (dbg_fd == -1) {
		dbg_exit
	}
}

static void process_cmd_start(struct task_info *entry)
{
	int ret, user_pts_fd, pid;
	char *user_pts_name;
	ssize_t exp;

	exp = read(entry->timerfd, &exp, sizeof(ssize_t));
	if (exp != sizeof(ssize_t)) {
		return;
	}

	pid = fork();
	if (pid == -1) {
		dbg_exit
	}

	if (pid != 0) {
		/* if pid = 0, this is the first launch, but not restart */
		if (entry->pid == 0) {
			/* tell the user the first launch pid */
			ret = write(resp_fd, &pid, sizeof(int));
			if (ret != sizeof(int)) {
				dbg_exit
			}
		}

		entry->pid = pid;
		entry->cmd = CMD_NOP;

		return;
	}

	setsid();

	user_pts_fd = posix_openpt(O_RDWR);
	if (user_pts_fd == -1) {
		dbg_exit
	}

	ret = grantpt(user_pts_fd);
	if (ret == -1) {
		dbg_exit
	}

	ret = unlockpt(user_pts_fd);
	if (ret == -1) {
		dbg_exit
	}

	user_pts_name = ptsname(user_pts_fd);
	if (user_pts_name == NULL) {
		dbg_exit
	}

	ret = ioctl(user_pts_fd, TIOCSCTTY, 0);
	if (ret == -1) {
		dbg_exit
	}

	ret = dup2(user_pts_fd, STDIN_FILENO);
	if (ret != STDIN_FILENO) {
		dbg_exit
	}

	ret = dup2(user_pts_fd, STDOUT_FILENO);
	if (ret != STDOUT_FILENO) {
		dbg_exit
	}

	ret = dup2(user_pts_fd, STDERR_FILENO);
	if (ret != STDERR_FILENO) {
		dbg_exit
	}

	execvpe(entry->argv[0], entry->argv, entry->envp);
}

static void process_cmd_exit(struct task_info *entry)
{
	int ret;

	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;

	ret = close(entry->timerfd);
	if (ret != 0) {
		dbg_exit
	}

	free(entry->argv);
	free(entry->envp);
	free(entry->arg_str);

	free(entry);
}

static void process_cmd_nop(struct task_info *entry)
{
	return;
}

static void (* process_cmd_func[CMD_COUNT])(struct task_info *entry) = {
	[CMD_START] = process_cmd_start,
	[CMD_EXIT] = process_cmd_exit,
	[CMD_NOP] = process_cmd_nop,
};

static void process_cmd(struct task_info *entry)
{
	process_cmd_func[entry->cmd](entry);
}

static void process_user_cmd(struct task_info *tmp_entry)
{
	struct task_info *entry;
	sigset_t block_mask, prev_mask;
	int i, j, ret;

	if (tmp_entry->cmd == CMD_EXIT) {
		for (entry = head->next; entry->pid != tmp_entry->pid; entry = entry->next) {
			continue;
		}

		entry->pid = 0;
		entry->cmd = CMD_EXIT;

		ret = kill(tmp_entry->pid, SIGKILL);
		if (ret != 0) {
			dbg_exit
		}

		return;
	}

	/* if (tmp_entry->cmd == CMD_START) code below */
	entry = malloc(sizeof(struct task_info));
	if (entry == NULL) {
		dbg_exit
	}

	memcpy(entry, tmp_entry, sizeof(struct task_info));

	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGCHLD);

	/* block SIGCHILD, because queue is shared for daemon and handler */
	ret = sigprocmask(SIG_BLOCK, &block_mask, &prev_mask);
	if (ret == -1) {
		dbg_exit
	}

	/* add new entry to queue */
	entry->prev = head->prev;
	entry->next = head;
	head->prev->next = entry;
	head->prev = entry;

	/* unblock SIGCHILD */
	ret = sigprocmask(SIG_SETMASK, &prev_mask, NULL);
	if (ret == -1) {
		dbg_exit
	}

	entry->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (entry->timerfd == -1) {
		dbg_exit
	}

	memset(&entry->ts, 0, sizeof(struct itimerspec));
	entry->ts.it_value.tv_sec = 1;
	ret = timerfd_settime(entry->timerfd, 0, &entry->ts, NULL);
	if (ret == -1) {
		dbg_exit
	}

	/* argv and envp parsing below */
	entry->arg_str = malloc(entry->arg_str_len);
	if (entry->arg_str == NULL) {
		dbg_exit
	}

	ret = read(argv_fd, entry->arg_str, entry->arg_str_len);
	if (ret != entry->arg_str_len) {
		dbg_exit
	}

	entry->argv = malloc(sizeof(char *) * (entry->argv_cnt + 1));
	if (entry->argv == NULL) {
		dbg_exit
	}

	entry->envp = malloc(sizeof(char *) * (entry->envp_cnt + 1));
	if (entry->envp == NULL) {
		dbg_exit
	}

	for (i = 0; i < entry->arg_str_len; i++) {
		if (entry->arg_str[i] == '\n') {
			entry->arg_str[i] = '\0';
		}
	}

	entry->argv[0] = &entry->arg_str[0];
	entry->argv[entry->argv_cnt] = NULL;
	entry->envp[entry->envp_cnt] = NULL;

	for (i = 0, j = 1; j != entry->argv_cnt; i++) {
		if (entry->arg_str[i] == '\0') {
			entry->argv[j] = &entry->arg_str[i + 1];
			j++;
		}
	}

	for (j = 0; j != entry->envp_cnt; i++) {
		if (entry->arg_str[i] == '\0') {
			entry->envp[j] = &entry->arg_str[i + 1];
			j++;
		}
	}
}

static void daemon_main_loop()
{
	struct task_info tmp_entry, *entry, *next;
	sigset_t block_mask, prev_mask;
	int ret;

	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGCHLD);

	while (1) {
		ret = read(ntfy_fd, &tmp_entry, sizeof(struct task_info));
		if (ret == sizeof(struct task_info)) {
			process_user_cmd(&tmp_entry);
		}

		/* block SIGCHILD, because queue is shared for daemon and handler */
		ret = sigprocmask(SIG_BLOCK, &block_mask, &prev_mask);
		if (ret == -1) {
			dbg_exit
		}

		/* starting, restarting, exiting processes cycle */
		for (entry = head->next; entry != head; entry = next) {
			next = entry->next;

			process_cmd(entry);
		}

		/* unblock SIGCHILD */
		ret = sigprocmask(SIG_SETMASK, &prev_mask, NULL);
		if (ret == -1) {
			dbg_exit
		}
	}
}

static void daemon_code()
{
	int ret;

	/* if file exists, daemon inited already, so execute only user code */
	ret = access(ARGV_FIFO, F_OK);
	if (ret == 0) {
		return;
	}

	/* if daemon didn't init */
	ret = become_daemon();
	if (ret != 0) {
		/* user code goes here and waits while daemon init */
		while (access(ARGV_FIFO, F_OK) != 0) {
			continue;
		}

		return;
	}

	/* daemon code goes here */

	daemon_setup();

	daemon_main_loop();
}

static void user_code(int argc, char **argv, char **envp)
{
	int ret, i, total_argv_strlen, offset, pid;
	struct task_info entry;
	char *arg_str, *endptr;

	if (argc < 3) {
		help_msg();
		return;
	}

	if (!strcmp(argv[1], "start") && !strcmp(argv[1], "exit")) {
		help_msg();
		return;
	}

	memset(&entry, 0, sizeof(struct task_info));

	if (strcmp(argv[1], "start") == 0) {
		entry.cmd = CMD_START;

		/* calculate total_strlen of all argv */
		for (total_argv_strlen = 0, i = 0; argv[2 + i] != NULL; i++) {
			total_argv_strlen += strlen(argv[2 + i]) + 1;
		}

		/* plus total_strlen of all envp */
		for (i = 0; envp[i] != NULL; i++) {
			total_argv_strlen += strlen(envp[i]) + 1;
		}

		arg_str = malloc(total_argv_strlen);
		if (arg_str == NULL) {
			dbg_exit
		}

		entry.argv_cnt = argc - 2;
		entry.arg_str_len = total_argv_strlen;

		/* copy all argv to arg_str */
		for (i = 0, offset = 0; argv[2 + i] != NULL; i++) {
			strncpy(arg_str + offset, argv[2 + i], strlen(argv[2 + i]));
			offset += strlen(argv[2 + i]) + 1;
			arg_str[offset - 1] = '\n';
		}

		/* copy all envp to arg_str */
		for (i = 0, entry.envp_cnt = 0; envp[i] != NULL; i++, entry.envp_cnt++) {
			strncpy(arg_str + offset, envp[i], strlen(envp[i]));
			offset += strlen(envp[i]) + 1;
			arg_str[offset - 1] = '\n';
		}
		arg_str[offset - 1] = '\0';
	}

	if (strcmp(argv[1], "exit") == 0) {
		entry.cmd = CMD_EXIT;

		errno = 0;
		entry.pid = strtol(argv[2], &endptr, 0);
		if (errno != 0) {
			dbg_exit
		}
		if (*endptr != '\0') {
			dbg_exit
		}
		if (entry.pid <= 0) {
			dbg_exit
		}
	}

	ntfy_fd = open(NTFY_FIFO, O_WRONLY);
	if (ntfy_fd == -1) {
		dbg_exit
	}

	resp_fd = open(RESP_FIFO, O_RDONLY);
	if (resp_fd == -1) {
		dbg_exit
	}

	argv_fd = open(ARGV_FIFO, O_WRONLY);
	if (argv_fd == -1) {
		dbg_exit
	}

	flock(ntfy_fd, LOCK_EX);

	ret = write(ntfy_fd, &entry, sizeof(struct task_info));
	if (ret != sizeof(struct task_info)) {
		dbg_exit
	}

	if (strcmp(argv[1], "start") == 0) {
		ret = write(argv_fd, arg_str, total_argv_strlen);
		if (ret != total_argv_strlen) {
			dbg_exit
		}
	}

	flock(ntfy_fd, LOCK_EX);

	if (strcmp(argv[1], "start") == 0) {
		ret = read(resp_fd, &pid, sizeof(int));
		if (ret != sizeof(int)) {
			dbg_exit
		}

		printf("%d\n", pid);
		fflush(NULL);
	}

	ret = close(ntfy_fd);
	if (ret != 0) {
		dbg_exit
	}

	ret = close(resp_fd);
	if (ret != 0) {
		dbg_exit
	}

	ret = close(argv_fd);
	if (ret != 0) {
		dbg_exit
	}

	return;
}

int main(int argc, char **argv, char **envp)
{
	daemon_code();

	user_code(argc, argv, envp);

	return 0;
}
