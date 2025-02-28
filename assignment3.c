#define _POSIX_C_SOURCE 199309L // for sigaction struct
#define _GNU_SOURCE             // for realpath and sigaction struct
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>        // Error handling
#include <unistd.h>       // POSIX API (fork, execvp, getcwd)
#include <sys/types.h>    // Data types used in system calls (pid_t)
#include <sys/wait.h>     // Wait functions (waitpid, WIFEXITED, WEXITSTATUS)
#include <linux/limits.h> // Contains the PATH_MAX constant
#include <termios.h>      // Terminal I/O interface
#include <signal.h>       // Signal handling
#include <dirent.h>       // Directory handling
#include <fcntl.h>        // File control options (O_WRONLY, O_CREAT, O_TRUNC)

#define MAX_INPUT_LEN 1024 // Maximum input length for command line
#define MAX_ARGS 100       // Maximum number of arguments a command can have
#define MAX_JOBS 100       // Maximum number of jobs that can be tracked
#define MAX_HISTORY 100    // Maximum number of commands that can be stored in history

// ======================= ANSI Color Codes =======================

// UI colors (using ANSI Escape codes, syntax: \033[ <style> ; <text-color> ; <background-color> m)
/**
 * style: 0 (reset), 1 (bold), 4 (underline), 5 (blink), 7 (reverse), 8 (hidden)
 * text-color: 30 (black), 31 (red), 32 (green), 33 (yellow), 34 (blue), 35 (magenta), 36 (cyan), 37 (white)
 * background-color: 40 (black), 41 (red), 42 (green), 43 (yellow), 44 (blue), 45 (magenta), 46 (cyan), 47 (white)
 */

#define GREEN "\033[1;32m"  // Bold Green
#define YELLOW "\033[1;33m" // Bold Yellow
#define RESET "\033[0m"     // Reset to default color

// ======================= Global ENUMS =======================

enum KEY_ACTION
{
    KEY_NORMAL,
    ARROW_LEFT = 1000,
    ARROW_RIGHT,
    ARROW_UP,
    ARROW_DOWN,
    HOME_KEY,
    END_KEY,
    DEL_KEY,
    TAB_KEY,
    BACKSPACE = 127
}; // enum for special and normal keys

typedef enum
{
    RUNNING,
    STOPPED,
    DONE
} JobStatus; // enum for job status

// ======================= Global Structs =======================

/**
 * Struct to store job information
 */

typedef struct
{
    pid_t pgid;       // process group ID
    char *cmd;        // command string
    JobStatus status; // Jobstatus
    bool is_fg;       // is foreground or not
} Job;

/**
 * Struct to store redirection information
 */

typedef struct
{
    char *stdin_file;  // stdin file
    char *stdout_file; // stdout file
    char *stderr_file; // stderr file
} redirect_info;

// ======================= Global States =======================

struct termios orig_termios; // original terminal settings
char input[MAX_INPUT_LEN];   // input buffer
int cursor_pos = 0;          // cursor position
int input_len = 0;           // user input length
Job job_list[MAX_JOBS];      // job list
int job_count = 0;           // number of jobs
pid_t shell_pgid;            // shell process group ID
char *history[MAX_HISTORY];  // command history
int history_count = 0;       // number of commands in history

// ======================== Job handling ========================

/**
 * Function to add a job to the job list
 * @param pgid The process group ID of the job
 * @param cmd The command string of the job
 * @param is_fg Flag to indicate if the job is in the foreground
 * @return void
 */
void add_job(pid_t pgid, const char *cmd, bool is_fg)
{
    if (job_count >= MAX_JOBS)
        return;
    job_list[job_count] = (Job){
        .pgid = pgid,
        .cmd = strdup(cmd),
        .status = RUNNING,
        .is_fg = is_fg};
    job_count++;
}

/**
 * Function to update the status of a job in the job list
 * @param pid The process ID of the job
 * @param status The new status of the job
 * @return void
 */
void update_job_status(pid_t pid, JobStatus status)
{
    for (int i = 0; i < job_count; i++)
    {
        if (job_list[i].pgid == pid)
        {
            job_list[i].status = status;
            return;
        }
    }
}

/**
 * Function to print the list of jobs
 * @param void
 * @return void
 */

void print_jobs()
{
    printf("Job List:\n");
    for (int i = 0; i < job_count; i++)
    {
        if (job_list[i].status != DONE)
        {
            printf("[%d] %d %s\t%s\n", i + 1, job_list[i].pgid,
                   job_list[i].status == RUNNING ? "Running" : "Stopped",
                   job_list[i].cmd);
        }
    }
}

/**
 * Function to continue a job in the job list
 * @param job_idx The index of the job in the job list
 * @param is_fg Flag to indicate if the job should be continued in the foreground
 * @return void
 */

void continue_job(int job_idx, bool is_fg)
{
    if (job_idx < 0 || job_idx >= job_count)
    {
        printf("Invalid job index\n");
        return;
    }

    Job *job = &job_list[job_idx];

    if (job->status == DONE)
    {
        printf("Job [%d] has already completed\n", job_idx + 1);
        return;
    }

    // Resume job if it was stopped
    kill(-job->pgid, SIGCONT);
    job->status = RUNNING;
    job->is_fg = is_fg;

    if (is_fg)
    {
        tcsetpgrp(STDIN_FILENO, job->pgid);

        int status;
        waitpid(-job->pgid, &status, WUNTRACED);

        if (WIFSTOPPED(status))
        {
            job->status = STOPPED;
        }
        else
        {
            job->status = DONE;
        }

        // Return control back to shell
        tcsetpgrp(STDIN_FILENO, shell_pgid);
    }
}

/**
 * Function to cleanup the job list by removing completed jobs
 * @param void
 * @return void
 */

void cleanup_jobs()
{
    int status;
    for (int i = 0; i < job_count; i++)
    {
        if (job_list[i].status == DONE)
            continue;

        pid_t result = waitpid(-job_list[i].pgid, &status, WNOHANG);
        if (result > 0)
        {
            if (WIFEXITED(status) || WIFSIGNALED(status))
            {
                printf("[%d] Done %s\n", job_list[i].pgid, job_list[i].cmd);
                job_list[i].status = DONE;
            }
            else if (WIFSTOPPED(status))
            {
                job_list[i].status = STOPPED;
            }
        }
    }
}

// ======================== Signal Handling =======================

/**
 * Signal handler for SIGCHLD
 * @param sig The signal number
 * @return void
 */
void handle_sigint(int sig)
{
    if (job_count > 0 && job_list[job_count - 1].is_fg)
        kill(job_list[job_count - 1].pgid, SIGINT);
}

/**
 * Signal handler for SIGTSTP
 * @param sig The signal number
 * @return void
 */

void handle_sigtstp(int sig)
{
    if (job_count > 0 && job_list[job_count - 1].is_fg)
    {
        kill(job_list[job_count - 1].pgid, SIGTSTP);
    }
}

/**
 * Signal handler for SIGCHLD to reap exited or stopped children
 * @param sig The signal number
 * @return void
 */
void handle_sigchld(int sig)
{
    int status;
    pid_t pid;

    // Loop to reap all exited children
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0)
    {
        for (int i = 0; i < job_count; i++)
        {
            if (job_list[i].pgid == pid)
            {
                if (WIFEXITED(status) || WIFSIGNALED(status))
                {
                    printf("[%d] Done %s\n", job_list[i].pgid, job_list[i].cmd);
                    job_list[i].status = DONE;
                }
                else if (WIFSTOPPED(status))
                {
                    job_list[i].status = STOPPED;
                }
                break;
            }
        }
    }
}

/**
 * Function to setup signal handlers for SIGINT and SIGTSTP
 * @param void
 * @return void
 */
void setup_signal_handlers()
{
    struct sigaction sa;

    // Handle SIGCHLD
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    // handlers for SIGINT and SIGTSTP
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);

    sa.sa_handler = handle_sigtstp;
    sigaction(SIGTSTP, &sa, NULL);
}

// ======================== TAB completion ========================

/**
 * Function to get the word being completed at the current cursor position
 * @param input The input string
 * @param cursor_pos The current cursor position
 * @param start Pointer to store the start position of the word
 * @param end Pointer to store the end position of the word
 * @return void
 */
void get_word_bounds(const char *input, int cursor_pos, int *start, int *end)
{
    // Find start of word
    *start = cursor_pos;
    while (*start > 0 && input[*start - 1] != ' ' && input[*start - 1] != '/')
    {
        (*start)--;
    }

    // Find end of word
    *end = cursor_pos;
    while (input[*end] != '\0' && input[*end] != ' ')
    {
        (*end)++;
    }
}

/**
 * Function to get the directory path from the current word
 * @param word The current word being completed
 * @param dir_path Buffer to store the directory path
 * @return void
 */
void get_dir_path(const char *word, char *dir_path)
{
    char *last_slash = strrchr(word, '/');
    if (last_slash)
    {
        strncpy(dir_path, word, last_slash - word + 1);
        dir_path[last_slash - word + 1] = '\0';
    }
    else
    {
        dir_path[0] = '.';
        dir_path[1] = '\0';
    }
}

// ======================== Redirection/Pipes ========================

/**
 * Function to parse redirection operators and filenames from the command arguments
 * @param args The command arguments
 * @return The redirection information
 */

redirect_info parse_redirection(char **args)
{
    redirect_info r = {NULL, NULL, NULL};
    int i = 0, j = 0;

    while (args[i])
    {
        // Handle a single token "2>"
        if (strcmp(args[i], "2>") == 0 && args[i + 1])
        {
            r.stderr_file = args[i + 1];
            args[i] = args[i + 1] = NULL;
            i += 2;
        }
        // Handle split tokens: "2" followed by ">"
        else if (strcmp(args[i], "2") == 0 && args[i + 1] && strcmp(args[i + 1], ">") == 0 && args[i + 2])
        {
            r.stderr_file = args[i + 2];
            args[i] = args[i + 1] = args[i + 2] = NULL;
            i += 3;
        }
        else if (strcmp(args[i], "<") == 0 && args[i + 1])
        {
            r.stdin_file = args[i + 1];
            args[i] = args[i + 1] = NULL;
            i += 2;
        }
        else if (strcmp(args[i], ">") == 0 && args[i + 1])
        {
            r.stdout_file = args[i + 1];
            args[i] = args[i + 1] = NULL;
            i += 2;
        }
        else
        {
            args[j++] = args[i++];
        }
    }
    args[j] = NULL;
    return r;
}

/**
 * Function to execute piped commands
 * @param commands An array of commands where each command is an array of arguments
 * @param num_commands The number of commands
 * @return void
 */

void execute_piped_commands(char ***commands, int num_commands)
{
    int pipes[num_commands - 1][2];
    pid_t pids[num_commands];

    // Create all pipes
    for (int i = 0; i < num_commands - 1; i++)
    {
        if (pipe(pipes[i]) == -1)
        {
            perror("pipe");
            return;
        }
    }

    pid_t pgid = 0;
    for (int i = 0; i < num_commands; i++)
    {
        if ((pids[i] = fork()) == -1)
        {
            perror("fork");
            return;
        }

        if (pids[i] == 0)
        { // Child process
            setpgid(0, pgid ? pgid : getpid());

            // Set up stdin from previous pipe
            if (i > 0)
            {
                if (dup2(pipes[i - 1][0], STDIN_FILENO) == -1)
                {
                    perror("dup2");
                    exit(1);
                }
            }

            // Set up stdout to next pipe
            if (i < num_commands - 1)
            {
                if (dup2(pipes[i][1], STDOUT_FILENO) == -1)
                {
                    perror("dup2");
                    exit(1);
                }
            }

            // Close all pipe fds in child
            for (int j = 0; j < num_commands - 1; j++)
            {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }

            // Handle redirections for first and last commands
            if (i == 0)
            {
                redirect_info r = parse_redirection(commands[i]);
                if (r.stdin_file)
                {
                    int fd = open(r.stdin_file, O_RDONLY);
                    if (fd != -1)
                    {
                        dup2(fd, STDIN_FILENO);
                        close(fd);
                    }
                }
            }

            if (i == num_commands - 1)
            {
                redirect_info r = parse_redirection(commands[i]);
                if (r.stdout_file)
                {
                    int fd = open(r.stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd != -1)
                    {
                        dup2(fd, STDOUT_FILENO);
                        close(fd);
                    }
                }
            }

            // Make sure stdout is line buffered
            setvbuf(stdout, NULL, _IOLBF, 0);

            if (execvp(commands[i][0], commands[i]) == -1)
            {
                fprintf(stderr, "Command not found: %s\n", commands[i][0]);
                exit(127);
            }
        }
        else
        { // Parent process
            if (i == 0)
            {
                pgid = pids[i];
            }
            setpgid(pids[i], pgid);
        }
    }

    // Parent process: Close all pipe fds
    for (int i = 0; i < num_commands - 1; i++)
    {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    // Add job and set process group
    add_job(pgid, commands[0][0], true);
    tcsetpgrp(STDIN_FILENO, pgid);

    // Wait for all processes to complete
    for (int i = 0; i < num_commands; i++)
    {
        int status;
        waitpid(pids[i], &status, WUNTRACED);

        if (i == num_commands - 1)
        { // Only update status for the last process
            if (WIFSTOPPED(status))
            {
                update_job_status(pgid, STOPPED);
            }
            else
            {
                update_job_status(pgid, DONE);
            }
        }
    }

    // Return terminal control to shell
    tcsetpgrp(STDIN_FILENO, shell_pgid);
}

// ======================== Command Execution Functions ========================

/**
 * Function to get the prompt string
 * @param void
 * @return The prompt string
 */
char *get_prompt()
{
    char cwd[PATH_MAX]; // buffer to store the current working directory
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        perror("getcwd failed");
        return strdup(GREEN "$ " RESET);
    }

    char *prompt = malloc(PATH_MAX + 20); // allocate memory for the prompt string
    if (!prompt)
    {
        perror("malloc failed");
        return strdup(GREEN "$ " RESET);
    }

    sprintf(prompt, YELLOW "%s" GREEN "$ " RESET, cwd); // format the prompt string
    return prompt;
}

/**
 * Function to get the path of the executable
 * @param buffer A buffer to store the path
 * @param size The size of the buffer
 * @return void
 */

void get_executable_path(char *buffer, size_t size)
{
    ssize_t len = readlink("/proc/self/exe", buffer, size - 1); // read the symbolic link of the executable
    if (len != -1)
        buffer[len] = '\0'; // null terminate the string
    else
    {
        perror("readlink failed");
        buffer[0] = '\0'; // return an empty string if readlink fails
    }
}

/**
 * Function to parse the user input into individual arguments
 * @param line the command line input string
 * @param args An array to store parsed arguments
 * @return void
 */

void parse_command(char *line, char **args)
{
    int i = 0;   // index for the args array
    char *token; // pointer to store each token extracted from line
    while (*line && i < MAX_ARGS - 1)
    {
        // handle brackets
        while (*line == ' ' || *line == '\t') // skip leading spaces
            line++;

        if (*line == '"' || *line == '\'') // handle quoted arguments
        {
            char quote = *line++; // Store quote type (single or double)
            token = line;         // Store the token after the quote

            while (*line && *line != quote) // Find the closing quote
                line++;

            if (*line)
                *line++ = '\0'; // Null terminate the token
        }
        else
        {
            token = line;
            while (*line && *line != ' ' && *line != '\t') // extract the token until a space or tab is encountered
                line++;
            if (*line)
                *line++ = '\0'; // Null terminate the token
        }

        args[i++] = token;
    }
    args[i] = NULL;
}

/**
 * Function to execute the parsed command
 * @param args An array of arguments to be passed to the command where args[0] is the command itself
 * @return void
 */

void execute_command(char **args)
{
    cleanup_jobs(); // Remove zombie processes before executing a new command

    // handle echo $$
    if (args[0] && strcmp(args[0], "echo") == 0 && args[1] && strcmp(args[1], "$$") == 0)
    {
        printf("%d\n", getpid());
        return;
    }

    // handle cd command
    if (strcmp(args[0], "cd") == 0)
    {
        const char *target = (args[1] != NULL) ? args[1] : getenv("HOME"); // Go to HOME if no argument
        if (chdir(target) != 0)
        {
            perror("cd failed");
        }
        return;
    }

    // jobs
    if (strcmp(args[0], "jobs") == 0)
    {
        print_jobs();
        return;
    }

    // fg
    if (strcmp(args[0], "fg") == 0)
    {
        if (args[1])
        {
            int job_idx = atoi(args[1]) - 1;
            if (job_idx < 0 || job_idx >= job_count)
            {
                printf("Invalid job number\n");
            }
            else
            {
                continue_job(job_idx, true);
            }
        }
        else
        {
            printf("Usage: fg <job-number>\n");
        }
        return;
    }

    // bg
    if (strcmp(args[0], "bg") == 0)
    {
        if (args[1])
        {
            int job_idx = atoi(args[1]) - 1;
            if (job_idx < 0 || job_idx >= job_count)
            {
                printf("Invalid job number\n");
            }
            else
            {
                continue_job(job_idx, false);
            }
        }
        else
        {
            printf("Usage: bg <job-number>\n");
        }
        return;
    }

    // handle kill
    if (strcmp(args[0], "kill") == 0)
    {
        if (!args[1])
        {
            printf("Usage: kill [-SIGNAL] PID\n");
            return;
        }

        int sig = SIGTERM; // Default signal
        int arg_idx = 1;

        // Check if the argument is a signal specification
        if (args[1][0] == '-')
        {
            char *sig_str = args[1] + 1;
            if (strcmp(sig_str, "CONT") == 0)
            {
                sig = SIGCONT;
            }
            else
            {
                sig = atoi(sig_str);
            }
            arg_idx++;
        }

        pid_t pid = atoi(args[arg_idx]);
        if (kill(pid, sig) == -1)
        {
            perror("kill failed");
        }
        else
        {
            // Update job status if the process is part of a job
            for (int i = 0; i < job_count; i++)
            {
                if (job_list[i].pgid == pid)
                {
                    if (sig == SIGCONT)
                    {
                        job_list[i].status = RUNNING;
                        job_list[i].is_fg = false; // Or handle foreground/background as needed
                    }
                    else if (sig == SIGTERM || sig == SIGKILL)
                    {
                        job_list[i].status = DONE;
                    }
                    break;
                }
            }
        }
        return;
    }

    // print out history
    if (strcmp(args[0], "history") == 0)
    {
        int index = 0;
        printf("\n");
        while (index != history_count)
        {
            printf("%d. %s\n", index + 1, history[index]);
            index++;
        }
        printf("\n");
        return;
    }

    // Handle pipes
    int pipe_count = 0;
    for (int i = 0; args[i]; i++)
        if (strcmp(args[i], "|") == 0)
            pipe_count++;

    if (pipe_count > 0)
    {
        char ***commands = malloc((pipe_count + 1) * sizeof(char **));
        int cmd_idx = 0;
        commands[cmd_idx++] = args;

        for (int i = 0; args[i]; i++)
        {
            if (strcmp(args[i], "|") == 0)
            {
                commands[cmd_idx++] = &args[i + 1];
                args[i] = NULL;
            }
        }

        execute_piped_commands(commands, pipe_count + 1);
        free(commands);
        return;
    }

    bool background = false; // flag to indicate if the command should be run in the background
    int i = 0;               // index for the array
    while (args[i] != NULL)
        i++;
    if (i > 0 && strcmp(args[i - 1], "&") == 0)
    {
        background = 1;
        args[i - 1] = NULL;
    }

    // handle recursive shell execution
    char exe_path[PATH_MAX]; // Store current executable path
    get_executable_path(exe_path, sizeof(exe_path));

    pid_t pid = fork(); // fork a new process

    if (pid < 0) // child process creation failed
    {
        perror("fork failed");
        return;
    }

    // child process
    if (pid == 0)
    {
        setpgid(0, 0); // set the process group ID

        if (!background)
            tcsetpgrp(STDIN_FILENO, getpid()); // set the terminal foreground process group

        signal(SIGINT, SIG_DFL);  // reset the signal handler for SIGINT (Ctrl+C)
        signal(SIGTSTP, SIG_DFL); // reset the signal handler for SIGTSTP (Ctrl+Z)

        char cmd_path[PATH_MAX];                 // Store the path of the command
        if (realpath(args[0], cmd_path) == NULL) // resolve path
        {
            snprintf(cmd_path, sizeof(cmd_path), "%s/%s", "/bin", args[0]);
            if (realpath(cmd_path, cmd_path) == NULL)
            {
                strcpy(cmd_path, args[0]);
            }
        }

        // Check against current shell's executable path
        if (strcmp(cmd_path, exe_path) == 0)
        {
            fprintf(stderr, "Recursive shell execution detected! Exiting.\n");
            exit(1);
        }

        redirect_info r = parse_redirection(args); // parse redirection arguments
        if (r.stdin_file)
        {
            int fd = open(r.stdin_file, O_RDONLY);
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        if (r.stdout_file)
        {
            int fd = open(r.stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
        if (r.stderr_file)
        {
            int fd = open(r.stderr_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }

        // Execute the command
        if (execvp(args[0], args) == -1)
        {
            fprintf(stderr, "Command %s not found.\n", args[0]);
            exit(1);
        }
    }
    else // parent process
    {
        if (background)
        {
            add_job(pid, args[0], false);
            printf("[%d] Running in background: %s\n", pid, args[0]);
        }
        else
        {
            add_job(pid, args[0], true);
            tcsetpgrp(STDIN_FILENO, pid); // set the terminal foreground process group

            int status;
            waitpid(pid, &status, WUNTRACED); // wait for the child process to complete

            // Update the job's status based on waitpid result
            if (job_count > 0)
            {
                Job *job = &job_list[job_count - 1];
                if (WIFEXITED(status) || WIFSIGNALED(status))
                {
                    job->status = DONE;
                }
                else if (WIFSTOPPED(status))
                {
                    job->status = STOPPED;
                }
            }

            tcsetpgrp(STDIN_FILENO, shell_pgid); // set the terminal foreground process group to the shell

            if (WIFEXITED(status))
            {
                printf("exited with code %d\n", WEXITSTATUS(status));
            }
            else if (WIFSIGNALED(status))
            {
                printf("\nterminated by signal %d\n", WTERMSIG(status));
            }
            else if (WIFSTOPPED(status))
            {
                printf("\nstopped by signal %d\n", WSTOPSIG(status)); // Handles Ctrl+Z (SIGTSTP)
            }
        }
        cleanup_jobs(); // clean up completed jobs
    }
}

/**
 * Function to preprocess the input line by adding spaces around redirection operators
 * @param line The input line
 * @return The preprocessed line
 */

char *preprocess_line(const char *line)
{
    // Allocate a new buffer, ensuring it's big enough.
    size_t len = strlen(line);
    char *new_line = malloc(len * 2 + 1); // worst-case scenario
    if (!new_line)
    {
        perror("malloc");
        exit(1);
    }
    size_t j = 0;
    for (size_t i = 0; i < len; i++)
    {
        // When you see a redirection operator, add a space before it
        if (line[i] == '<' || line[i] == '>')
        {
            if (j > 0 && new_line[j - 1] != ' ')
                new_line[j++] = ' ';
            new_line[j++] = line[i];
            // If next character is not a space, add a space after
            if (i + 1 < len && line[i + 1] != ' ')
                new_line[j++] = ' ';
        }
        else
        {
            new_line[j++] = line[i];
        }
    }
    new_line[j] = '\0';
    return new_line;
}

// ======================== Terminal Handling =======================

/**
 * Function to handle errors and exit the program
 * @param s The error message
 * @return void
 */

void die(const char *s)
{
    perror(s);
    exit(1);
}

/**
 * Function to disable raw mode for the terminal
 * @param void
 * @return void
 */

void disable_raw_mode()
{
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios) == -1)
        die("tcsetattr");
}

/**
 * Function to enable raw mode for the terminal
 * @param void
 * @return void
 */
void enable_raw_mode()
{
    if (tcgetattr(STDIN_FILENO, &orig_termios) == -1)
        die("tcgetattr");

    atexit(disable_raw_mode);

    struct termios raw = orig_termios;

    // Disable input processing
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    // Disable output processing
    raw.c_oflag &= ~(OPOST);

    // Set char size to 8 bits
    raw.c_cflag |= (CS8);

    // Disable echo and canonical mode
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

    // timeout for read()
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1)
        die("tcsetattr");
}

// ======================== Input Handling ========================

/**
 * Reads a single key from the terminal
 * @param void
 * @return The key from the terminal
 */

int read_key()
{
    char c;
    ssize_t nread;

    while ((nread = read(STDIN_FILENO, &c, 1)) != 1)
    {
        if (nread == -1 && errno != EAGAIN)
            die("read");
    }

    if (c == '\t')
    {
        return TAB_KEY;
    }

    if (c == '\x1b')
    {
        char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1)
            return '\x1b';
        if (read(STDIN_FILENO, &seq[1], 1) != 1)
            return '\x1b';

        if (seq[0] == '[')
        {
            switch (seq[1])
            {
            case 'A':
                return ARROW_UP;
            case 'B':
                return ARROW_DOWN;
            case 'C':
                return ARROW_RIGHT;
            case 'D':
                return ARROW_LEFT;
            case 'H':
                return HOME_KEY;
            case 'F':
                return END_KEY;
            case '3':
                if (read(STDIN_FILENO, &c, 1) == 1 && c == '~')
                    return DEL_KEY;
                return '\x1b';
            }
        }
        return '\x1b';
    }
    return c;
}

/**
 * Function to get the visible length of a string (excluding ANSI escape sequences)
 * @param str The input string
 * @return The visible length of the string
 */

size_t visible_length(const char *str)
{
    size_t len = 0;
    int in_escape = 0;

    for (; *str; str++)
    {
        if (*str == '\033')
        {
            in_escape = 1;
            continue;
        }
        if (in_escape)
        {
            if (*str == 'm')
                in_escape = 0;
            continue;
        }
        len++;
    }
    return len;
}

/**
 * Refreshes the displayed line with the prompt and current input
 * @param void
 * @return void
 */

void refresh_line()
{
    char *prompt = get_prompt();
    size_t prompt_len = visible_length(prompt);

    printf("\r\033[K%s%s", prompt, input);
    printf("\033[%zuG", prompt_len + cursor_pos + 1);
    fflush(stdout);
}

/**
 * Function to read a line of input from the user
 * @param void
 * @return The input string
 */
char *read_input()
{
    memset(input, 0, MAX_INPUT_LEN); // clear the input buffer
    cursor_pos = 0;                  // set the cursor position to the beginning
    input_len = 0;                   // set the input length to 0

    enable_raw_mode(); // enable raw mode for the terminal
    refresh_line();    // refresh the line

    int current_history_pos = history_count; // current position in the history

    while (1)
    {
        int key = read_key(); // read a single key from the terminal

        switch (key)
        {
        case '\r':
        case '\n':
            printf("\r\n");
            disable_raw_mode();      // disable raw mode for the terminal
            input[input_len] = '\0'; // null terminate the input buffer
            return strdup(input);    // return the input buffer

        case BACKSPACE:
            if (cursor_pos > 0)
            {
                // shift the characters to the left
                memmove(&input[cursor_pos - 1], &input[cursor_pos],
                        input_len - cursor_pos + 1);

                cursor_pos--;   // move the cursor to the left
                input_len--;    // decrease the input length
                refresh_line(); // refresh the line
            }
            break;
        case DEL_KEY:
            if (cursor_pos < input_len) // only delete if there's something to delete
            {
                // shift the characters to the left
                memmove(&input[cursor_pos], &input[cursor_pos + 1],
                        input_len - cursor_pos);

                input_len--;    // decrease the input length
                refresh_line(); // refresh the line
            }
            break;

        case HOME_KEY:
            cursor_pos = 0;
            refresh_line();
            break;

        case END_KEY:
            cursor_pos = input_len;
            refresh_line();
            break;

        case ARROW_LEFT:
            if (cursor_pos > 0)
                cursor_pos--;
            refresh_line();
            break;

        case ARROW_RIGHT:
            if (cursor_pos < input_len)
                cursor_pos++;
            refresh_line();
            break;

        case ARROW_UP:
            if (history_count > 0)
            {
                if (current_history_pos == history_count)
                {
                    current_history_pos = history_count - 1;
                }
                else if (current_history_pos > 0)
                {
                    current_history_pos--;
                }
                strncpy(input, history[current_history_pos], MAX_INPUT_LEN);
                input_len = strlen(input);
                cursor_pos = input_len;
                refresh_line();
            }
            break;
        case ARROW_DOWN:
            if (current_history_pos < history_count)
            {
                current_history_pos++;
                if (current_history_pos < history_count)
                {
                    strncpy(input, history[current_history_pos], MAX_INPUT_LEN);
                    input_len = strlen(input);
                    cursor_pos = input_len;
                }
                else
                {
                    memset(input, 0, MAX_INPUT_LEN);
                    input_len = 0;
                    cursor_pos = 0;
                }
                refresh_line();
            }
            break;

        case TAB_KEY:
        {
            int word_start, word_end;
            get_word_bounds(input, cursor_pos, &word_start, &word_end);

            char current_word[MAX_INPUT_LEN];
            strncpy(current_word, input + word_start, word_end - word_start);
            current_word[word_end - word_start] = '\0';

            char dir_path[MAX_INPUT_LEN];
            char file_prefix[MAX_INPUT_LEN];

            // Get directory path and file prefix
            get_dir_path(current_word, dir_path);

            char *last_slash = strrchr(current_word, '/');
            const char *prefix = last_slash ? last_slash + 1 : current_word;

            // Open the directory
            DIR *dir = opendir(dir_path);
            if (!dir)
            {
                break;
            }

            struct dirent *entry;
            char matches[MAX_HISTORY][MAX_INPUT_LEN];
            int match_count = 0;
            size_t prefix_len = strlen(prefix);

            // Find matching entries
            while ((entry = readdir(dir)) != NULL && match_count < MAX_HISTORY)
            {
                // Skip hidden files unless prefix starts with '.'
                if (entry->d_name[0] == '.' && prefix[0] != '.')
                {
                    continue;
                }
                if (strncmp(entry->d_name, prefix, prefix_len) == 0)
                {
                    snprintf(matches[match_count], MAX_INPUT_LEN, "%s", entry->d_name);
                    match_count++;
                }
            }
            closedir(dir);

            if (match_count == 1)
            {
                // Single match - auto-complete
                char new_word[MAX_INPUT_LEN];
                size_t required_len;

                if (strcmp(dir_path, ".") == 0)
                {
                    required_len = strlen(matches[0]);
                    if (required_len >= MAX_INPUT_LEN)
                    {
                        printf("\nPath too long for completion\n");
                        refresh_line();
                        break;
                    }
                    strncpy(new_word, matches[0], MAX_INPUT_LEN - 1);
                }
                else
                {
                    required_len = strlen(dir_path) + strlen(matches[0]);
                    if (required_len >= MAX_INPUT_LEN)
                    {
                        printf("\nPath too long for completion\n");
                        refresh_line();
                        break;
                    }
                    strncpy(new_word, dir_path, MAX_INPUT_LEN - 1);
                    strncat(new_word, matches[0], MAX_INPUT_LEN - strlen(new_word) - 1);
                }
                new_word[MAX_INPUT_LEN - 1] = '\0'; // Ensure null termination

                // Check if the completed path would exceed input buffer
                if (input_len - (word_end - word_start) + strlen(new_word) >= MAX_INPUT_LEN)
                {
                    printf("\nResulting command would be too long\n");
                    refresh_line();
                    break;
                }

                // Replace the current word with the completed one
                memmove(input + word_start + strlen(new_word),
                        input + word_end,
                        input_len - word_end + 1);
                memcpy(input + word_start, new_word, strlen(new_word));

                input_len = input_len + strlen(new_word) - (word_end - word_start);
                cursor_pos = word_start + strlen(new_word);
                refresh_line();
            }
            else if (match_count > 1)
            {
                // Move to new line and clear it
                printf("\r\n");
                printf("Possible completions:\n");

                // First pass: find the longest filename for proper column width
                int max_len = 0;
                for (int i = 0; i < match_count; i++)
                {
                    int len = strlen(matches[i]);
                    if (len > max_len)
                        max_len = len;
                }

                // Calculate column width with padding
                int col_width = max_len + 4; // Add some padding between columns
                int term_width = 80;         // Assume standard terminal width
                int cols = term_width / col_width;
                if (cols == 0)
                    cols = 1; // Ensure at least one column

                // Calculate number of rows needed
                int rows = (match_count + cols - 1) / cols;

                // Print in columns, going down then across
                for (int row = 0; row < rows; row++)
                {
                    for (int col = 0; col < cols; col++)
                    {
                        int idx = row + (col * rows);
                        if (idx < match_count)
                        {
                            printf("%-*s", col_width, matches[idx]);
                        }
                    }
                    printf("\n");
                }

                // Refresh the prompt and input line
                refresh_line();
            }
            break;
        }
        default:
            if (key >= 32 && key <= 126)
            {
                if (input_len < MAX_INPUT_LEN - 1)
                {
                    // shift the characters to the right
                    memmove(&input[cursor_pos + 1], &input[cursor_pos],
                            input_len - cursor_pos + 1);
                    input[cursor_pos] = key; // insert the character at the cursor position
                    cursor_pos++;            // move the cursor to the right
                    input_len++;             // increase the input length
                    refresh_line();
                }
            }
        }
    }
}

// ======================== Main Function ========================

int main(void)
{
    // Set up the shell's process group
    shell_pgid = getpid();
    setpgid(shell_pgid, shell_pgid);
    tcsetpgrp(STDIN_FILENO, shell_pgid); // Ensure shell owns the terminal

    // Ignore SIGTTOU to prevent shell from being suspended when handling jobs
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);

    setup_signal_handlers(); // setup signal handlers for SIGINT and SIGTSTP

    char *args[MAX_ARGS]; // array to store the parsed arguments

    while (1) // infinite loop to keep the shell running
    {

        char *raw_line = read_input();
        char *line = preprocess_line(raw_line);
        free(raw_line);

        if (!line || strlen(line) == 0)
        {
            printf("Use 'exit' to quit\n");
            free(line);
            continue;
        }

        // Add non-empty commands to history
        if (strlen(line) > 0)
        {
            if (history_count == MAX_HISTORY)
            {
                free(history[0]);
                for (int i = 0; i < MAX_HISTORY; i++)
                {
                    history[i] = history[i + 1];
                }
                history_count--;
            }
            history[history_count++] = strdup(line);
        }

        parse_command(line, args); // parse the input into arguments

        // exit
        if (strcmp(args[0], "exit") == 0)
        {
            bool jobs_remaining = false;
            for (int i = 0; i < job_count; i++)
            {
                if (job_list[i].status != DONE)
                {
                    jobs_remaining = true;
                    break;
                }
            }

            if (jobs_remaining)
            {
                printf("There are stopped/running jobs.\n");
                continue;
            }

            free(line);
            break;
        }

        if (args[0])
            execute_command(args); // execute the command

        free(line); // free the memory allocated for the input line
    }
    return 0;
}