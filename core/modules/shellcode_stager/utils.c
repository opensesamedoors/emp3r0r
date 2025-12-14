#include "utils.h"
#include "syscalls.h"
#include <stdarg.h>

// -----------------------------------------------------------------------------
// Memory Management (Simple Bump Allocator with Size Tracking)
// -----------------------------------------------------------------------------

#define HEAP_SIZE (128 * 1024 * 1024) // 128 MB heap

static uint8_t *heap_start = NULL;
static size_t heap_offset = 0;

void *malloc(size_t size) {
  if (size == 0)
    return NULL;

  if (heap_start == NULL) {
    // Initialize heap
    long ret = syscall6(SYS_mmap, 0, HEAP_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret < 0)
      return NULL; // Failed
    heap_start = (uint8_t *)ret;
  }

  size_t actual_size = size + sizeof(size_t);
  if (heap_offset + actual_size > HEAP_SIZE) {
    return NULL; // OOM
  }

  void *ptr = heap_start + heap_offset;
  *(size_t *)ptr = size; // Store size
  heap_offset += actual_size;

  // Align to 8 bytes
  if (heap_offset % 8 != 0) {
    heap_offset += 8 - (heap_offset % 8);
  }

  return (uint8_t *)ptr + sizeof(size_t);
}

void free(void *ptr) {
  // No-op for stager
  (void)ptr;
}

void *calloc(size_t nmemb, size_t size) {
  size_t total = nmemb * size;
  void *ptr = malloc(total);
  if (ptr) {
    memset(ptr, 0, total);
  }
  return ptr;
}

void *realloc(void *ptr, size_t size) {
  if (!ptr)
    return malloc(size);
  if (size == 0) {
    free(ptr);
    return NULL;
  }

  uint8_t *real_ptr = (uint8_t *)ptr - sizeof(size_t);
  size_t old_size = *(size_t *)real_ptr;
  size_t old_actual_size = old_size + sizeof(size_t);

  // Check if we can extend the current chunk
  size_t current_offset = (size_t)(real_ptr - heap_start);
  size_t expected_end = current_offset + old_actual_size;
  if (expected_end % 8 != 0) {
    expected_end += 8 - (expected_end % 8);
  }

  if (expected_end == heap_offset) {
    // This is the last chunk, try to extend
    size_t new_actual_size = size + sizeof(size_t);
    size_t new_end = current_offset + new_actual_size;
    if (new_end % 8 != 0) {
      new_end += 8 - (new_end % 8);
    }

    if (new_end <= HEAP_SIZE) {
      *(size_t *)real_ptr = size;
      heap_offset = new_end;
      return ptr;
    }
  }

  void *new_ptr = malloc(size);
  if (!new_ptr)
    return NULL;

  size_t copy_size = old_size < size ? old_size : size;
  memcpy(new_ptr, ptr, copy_size);

  return new_ptr;
}

// -----------------------------------------------------------------------------
// String / Memory
// -----------------------------------------------------------------------------

void *memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = (unsigned char *)dest;
  const unsigned char *s = (const unsigned char *)src;

  if (d == s || n == 0)
    return dest;

  // Handle overlap (memmove semantics)
  if ((uintptr_t)d < (uintptr_t)s) {
    while (n--)
      *d++ = *s++;
  } else {
    d += n;
    s += n;
    while (n--)
      *--d = *--s;
  }
  return dest;
}

void *memset(void *s, int c, size_t n) {
  unsigned char *p = (unsigned char *)s;
  while (n--)
    *p++ = (unsigned char)c;
  return s;
}

size_t strlen(const char *s) {
  size_t len = 0;
  while (*s++)
    len++;
  return len;
}

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
  while (n && *s1 && (*s1 == *s2)) {
    s1++;
    s2++;
    n--;
  }
  if (n == 0)
    return 0;
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

char *strstr(const char *haystack, const char *needle) {
  size_t nlen = strlen(needle);
  if (nlen == 0)
    return (char *)haystack;
  size_t hlen = strlen(haystack);
  if (hlen < nlen)
    return NULL;

  for (size_t i = 0; i <= hlen - nlen; i++) {
    if (strncmp(haystack + i, needle, nlen) == 0) {
      return (char *)(haystack + i);
    }
  }
  return NULL;
}

// Minimal snprintf (only supports %s and %d)
int snprintf(char *str, size_t size, const char *format, ...) {
  va_list args;
  va_start(args, format);

  char *out = str;
  const char *fmt = format;
  size_t remaining = size;

  while (*fmt && remaining > 1) {
    if (*fmt == '%') {
      fmt++;
      if (*fmt == 's') {
        char *s = va_arg(args, char *);
        while (*s && remaining > 1) {
          *out++ = *s++;
          remaining--;
        }
      } else if (*fmt == 'd') {
        int d = va_arg(args, int);
        char buf[32];
        int i = 0;
        if (d == 0) {
          buf[i++] = '0';
        } else {
          if (d < 0) {
            if (remaining > 1) {
              *out++ = '-';
              remaining--;
            }
            d = -d;
          }
          int temp = d;
          while (temp > 0) {
            temp /= 10;
            i++;
          }
          temp = d;
          for (int j = 0; j < i; j++) {
            buf[i - 1 - j] = (temp % 10) + '0';
            temp /= 10;
          }
        }
        for (int j = 0; j < i && remaining > 1; j++) {
          *out++ = buf[j];
          remaining--;
        }
      }
      fmt++;
    } else {
      *out++ = *fmt++;
      remaining--;
    }
  }
  *out = '\0';
  va_end(args);
  return out - str;
}

#ifdef DEBUG
void debug_print(const char *format, ...) {
  char buf[1024];
  va_list args;
  va_start(args, format);

  // We can't use vsnprintf because we don't have it.
  // So we have to reimplement the formatting logic or just use snprintf with a
  // fixed buffer if we had vsnprintf. Since we implemented snprintf manually
  // above using va_arg, we can't easily reuse it for debug_print which also
  // takes varargs. We need a vprintf-like helper. For now, let's just duplicate
  // the logic or make snprintf take va_list.

  // Let's refactor snprintf to use a helper vsnprintf
  // But for now, to save time/edits, I'll just implement a simple string
  // printer that supports %s and %d directly here.

  char *out = buf;
  const char *fmt = format;
  size_t remaining = sizeof(buf);

  while (*fmt && remaining > 1) {
    if (*fmt == '%') {
      fmt++;
      if (*fmt == 'l')
        fmt++; // Ignore 'l' modifier
      if (*fmt == 's') {
        char *s = va_arg(args, char *);
        if (!s)
          s = "(null)";
        while (*s && remaining > 1) {
          *out++ = *s++;
          remaining--;
        }
      } else if (*fmt == 'd' || *fmt == 'x' || *fmt == 'p') {
        // Simple hex/decimal support
        long d = 0;
        int is_hex = (*fmt == 'x' || *fmt == 'p');
        if (*fmt == 'p')
          d = (long)va_arg(args, void *);
        else
          d = va_arg(args, int);

        char num_buf[32];
        int i = 0;

        if (d == 0) {
          num_buf[i++] = '0';
        } else {
          unsigned long u = d;
          if (!is_hex && d < 0) {
            if (remaining > 1) {
              *out++ = '-';
              remaining--;
            }
            u = -d;
          }

          while (u > 0) {
            int digit = u % (is_hex ? 16 : 10);
            num_buf[i++] = (digit < 10) ? (digit + '0') : (digit - 10 + 'a');
            u /= (is_hex ? 16 : 10);
          }
        }
        for (int j = 0; j < i && remaining > 1; j++) {
          *out++ = num_buf[i - 1 - j];
          remaining--;
        }
      }
      fmt++;
    } else {
      *out++ = *fmt++;
      remaining--;
    }
  }
  *out = '\0';
  va_end(args);

  write(STDERR_FILENO, buf, out - buf);
}

void perror(const char *s) { debug_print("Error: %s\n", s); }
#else
void debug_print(const char *format, ...) { (void)format; }
void perror(const char *s) { (void)s; }
#endif

// -----------------------------------------------------------------------------
// Network / IP
// -----------------------------------------------------------------------------

unsigned short htons(unsigned short hostshort) {
  return (hostshort << 8) | (hostshort >> 8);
}

unsigned int htonl(unsigned int hostlong) {
  return ((hostlong & 0xFF000000) >> 24) | ((hostlong & 0x00FF0000) >> 8) |
         ((hostlong & 0x0000FF00) << 8) | ((hostlong & 0x000000FF) << 24);
}

int inet_aton(const char *cp, struct in_addr *inp) {
  unsigned int val = 0;
  int part = 0;
  int parts = 0;
  char c;

  while ((c = *cp++) != '\0') {
    if (c >= '0' && c <= '9') {
      part = part * 10 + (c - '0');
    } else if (c == '.') {
      if (part > 255)
        return 0;
      val = (val << 8) | part;
      part = 0;
      parts++;
    } else {
      return 0;
    }
  }
  if (part > 255 || parts != 3)
    return 0;
  val = (val << 8) | part;
  inp->s_addr = htonl(val);
  return 1;
}

// -----------------------------------------------------------------------------
// Random
// -----------------------------------------------------------------------------

long getrandom(void *buf, size_t buflen, unsigned int flags) {
  return syscall3(SYS_getrandom, (long)buf, buflen, flags);
}

// -----------------------------------------------------------------------------
// Syscall Wrappers
// -----------------------------------------------------------------------------

long write(int fd, const void *buf, size_t count) {
  return syscall3(SYS_write, fd, (long)buf, count);
}

long read(int fd, void *buf, size_t count) {
  return syscall3(SYS_read, fd, (long)buf, count);
}

long close(int fd) { return syscall1(SYS_close, fd); }

long exit(int error_code) { return syscall1(SYS_exit, error_code); }

long mmap(void *addr, size_t length, int prot, int flags, int fd, long offset) {
  // mmap arguments: addr, length, prot, flags, fd, offset
  // syscall arguments: rdi, rsi, rdx, r10, r8, r9
  // SYS_mmap is 9
  return syscall6(SYS_mmap, (long)addr, length, prot, flags, fd, offset);
}

long munmap(void *addr, size_t length) {
  return syscall2(SYS_munmap, (long)addr, length);
}

long mprotect(void *addr, size_t len, int prot) {
  return syscall3(SYS_mprotect, (long)addr, len, prot);
}

long fork(void) { return syscall0(SYS_fork); }

long pipe(int pipefd[2]) { return syscall1(SYS_pipe, (long)pipefd); }

long dup2(int oldfd, int newfd) { return syscall2(SYS_dup2, oldfd, newfd); }

long waitpid(int pid, int *status, int options) {
  return syscall4(SYS_wait4, pid, (long)status, options, 0);
}

long getuid(void) { return syscall0(SYS_getuid); }

long geteuid(void) { return syscall0(SYS_geteuid); }

long getgid(void) { return syscall0(SYS_getgid); }

long getegid(void) { return syscall0(SYS_getegid); }

// -----------------------------------------------------------------------------
// Socket Wrappers
// -----------------------------------------------------------------------------

int socket(int domain, int type, int protocol) {
  return (int)syscall3(SYS_socket, domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, unsigned int addrlen) {
  return (int)syscall3(SYS_connect, sockfd, (long)addr, addrlen);
}

long send(int sockfd, const void *buf, size_t len, int flags) {
  return syscall6(SYS_sendto, sockfd, (long)buf, len, flags, 0, 0);
}

long recv(int sockfd, void *buf, size_t len, int flags) {
  return syscall6(SYS_recvfrom, sockfd, (long)buf, len, flags, 0, 0);
}

long sendto(int sockfd, const void *buf, size_t len, int flags,
            const struct sockaddr *dest_addr, unsigned int addrlen) {
  return syscall6(SYS_sendto, sockfd, (long)buf, len, flags, (long)dest_addr,
                  addrlen);
}

long recvfrom(int sockfd, void *buf, size_t len, int flags,
              struct sockaddr *src_addr, unsigned int *addrlen) {
  return syscall6(SYS_recvfrom, sockfd, (long)buf, len, flags, (long)src_addr,
                  (long)addrlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval,
               unsigned int optlen) {
  return (int)syscall5(SYS_setsockopt, sockfd, level, optname, (long)optval,
                       optlen);
}
