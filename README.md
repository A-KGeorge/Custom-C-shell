# Custom Shell Implementation

## Overview

This is a custom Unix shell implemented in C. It supports various built-in commands, job control, input/output redirection, pipes, tab completion, history tracking, and interactive line editing. The shell provides an intuitive interface for command execution with additional features commonly found in modern shells.

## Features

### 1. **Command Execution**

- Supports execution of external programs using `fork()` and `execvp()`.
- Supports background execution using `&`.
- Prevents recursive execution of itself.

### 2. **Built-in Commands**

- `cd <directory>`: Changes the current working directory.
- `history`: Displays command history for the current session.
- `jobs`: Lists background jobs.
- `fg <job-number>`: Moves a background job to the foreground.
- `bg <job-number>`: Resumes a suspended job in the background.
- `kill [-SIGNAL] <PID>`: Sends a signal to a process.
- `exit`: Exits the shell if there are no running jobs.

### 3. **Cancellation (SIGINT - Ctrl+C)**

- Handles `Ctrl+C` to terminate a currently running child process rather than the shell itself.

### 4. **Suspension (SIGTSTP - Ctrl+Z)**

- Handles `Ctrl+Z` to suspend a currently running child process instead of the shell.

### 5. **Job Control**

- Implements job tracking with `fg` and `bg` commands.
- Uses `SIGTTOU` and `SIGTTIN` handling to ensure proper job control behavior.
- Stores job status (running, stopped, done) in a job table.

### 6. **History Tracking**

- Stores up to 100 previous commands.
- Supports `history` command to view past commands.
- Supports navigation through history using `↑` (up arrow) and `↓` (down arrow) keys.

### 7. **Line Editing**

- Enables interactive editing using left (`←`) and right (`→`) arrow keys.
- Supports backspace and delete key for modifying input.
- Handles home (`Home` key) and end (`End` key) key functionalities.

### 8. **Pipes (`|`)**

- Supports multiple piped commands (e.g., `ls | grep txt | wc -l`).
- Uses `dup2()` to redirect standard output to the next command in the pipeline.

### 9. **Redirection (`<`, `>`, `2>`)**

- Redirects input using `< file`.
- Redirects output using `> file`.
- Redirects standard error output using `2> file`.
- Supports redirection with piped commands.

### 10. **Tab Completion**

- Pressing `Tab` attempts to auto-complete a partially typed filename.
- Displays matching filenames if multiple options exist.

## Compilation and Execution

To compile the shell, run:

```sh
gcc assignment3.c -o mysh
```

To start the shell, run:

```sh
./mysh
```

## Usage Examples

```sh
$ ls | grep .c > output.txt   # Pipes and output redirection
$ echo hello > file.txt       # Redirect output to a file
$ cat < file.txt              # Redirect input from a file
$ ls &                        # Run process in the background
$ fg 1                        # Bring background job 1 to foreground
$ history                     # Show command history
$ cd /home                    # Change directory
$ kill -9 1234                # Kill process with PID 1234
```

## License

This project is open-source and available for modification and distribution.

## Author

- Developed as part of an academic assigment in C programming.
