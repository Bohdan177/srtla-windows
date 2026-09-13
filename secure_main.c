/*
 * CLI wrapper for srtla_rec Stream ID authentication.
 *
 * srtla_rec.c is compiled with main renamed to srtla_original_main. This
 * wrapper consumes --stream-id before handing the remaining arguments to the
 * original receiver.
 */

#include "streamid_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int srtla_original_main(int argc, char **argv);

static void print_stream_id_help(void) {
  fprintf(stderr,
          "\nSecurity option:\n"
          "  --stream-id ID       Require an exact SRT Stream ID before accepting a stream\n"
          "  --stream-id=ID       Same as above\n"
          "\nExample:\n"
          "  srtla_rec.exe 7000 127.0.0.1 5002 --stream-id my-secret --log-errors\n\n");
}

int main(int argc, char **argv) {
  char **filtered = (char **)calloc((size_t)argc + 1u, sizeof(char *));
  if (filtered == NULL) {
    fprintf(stderr, "Failed to allocate argument buffer\n");
    return EXIT_FAILURE;
  }

  int filtered_argc = 0;
  int stream_id_seen = 0;
  filtered[filtered_argc++] = argv[0];

  for (int i = 1; i < argc; ++i) {
    const char *stream_id = NULL;

    if (strcmp(argv[i], "--stream-id") == 0) {
      if (stream_id_seen) {
        fprintf(stderr, "--stream-id may only be specified once\n");
        free(filtered);
        return EXIT_FAILURE;
      }
      if (i + 1 >= argc) {
        fprintf(stderr, "--stream-id requires a value\n");
        print_stream_id_help();
        free(filtered);
        return EXIT_FAILURE;
      }
      stream_id = argv[++i];
    } else if (strncmp(argv[i], "--stream-id=", 12) == 0) {
      if (stream_id_seen) {
        fprintf(stderr, "--stream-id may only be specified once\n");
        free(filtered);
        return EXIT_FAILURE;
      }
      stream_id = argv[i] + 12;
    }

    if (stream_id != NULL) {
      if (streamid_auth_set_expected(stream_id) != 0) {
        fprintf(stderr, "Invalid --stream-id: value must be 1 to 512 bytes\n");
        free(filtered);
        return EXIT_FAILURE;
      }
      stream_id_seen = 1;
      continue;
    }

    if (strcmp(argv[i], "--help-stream-id") == 0) {
      print_stream_id_help();
      free(filtered);
      return EXIT_SUCCESS;
    }

    filtered[filtered_argc++] = argv[i];
  }

  filtered[filtered_argc] = NULL;
  int result = srtla_original_main(filtered_argc, filtered);
  free(filtered);
  return result;
}
