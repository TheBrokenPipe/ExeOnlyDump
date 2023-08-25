#ifndef HELPER_H
#define HELPER_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

/* CONSOLE I/O HELPERS */
void out_text(const char *format, ...);
void out_error_raw(const char *format, ...);
#define out_error(...) out_error_raw("[%s] ", __func__); out_error_raw(__VA_ARGS__)
#define err_msg(...) out_error_raw(__VA_ARGS__)
char *input_line(void);

/* CONVERSION HELPERS */
char *str_to_upper(char *str);
bool str_to_ull(const char *str, unsigned long long *result);

/* USER INPUT PROMPTS */
bool prompt_yes_no(void);
unsigned long long prompt_ull(void);
char *prompt_str(void);

/* FILE I/O */
bool ensure_file_exists(const char *filename);
bool get_file_size(const char *filename, off_t *size);
bool set_file_size(const char *filename, off_t size);
bool dup_file_size(const char *outfile, const char *infile);
void set_perms(const char *filename);

/* MISC. HELPERS */
void hex_dump(const void *ptr, size_t size, unsigned long base);
bool wait_child(pid_t pid);
void kill_child(pid_t pid);

#endif /* HELPER_H */
