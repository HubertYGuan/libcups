//
// Unit test header for C/C++ programs.
//
// Copyright © 2021-2022 by Michael R Sweet.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//

#ifndef TEST_H
#  define TEST_H
#  include <stdio.h>
#  include <stdlib.h>
#  include <zephyr/sys/cbprintf.h>
#  include <stdbool.h>
#  include <string.h>
#  if _WIN32
#    define isatty(f) _isatty(f)
#  else
#    include <unistd.h>
#    include <zephyr/fs/fs.h>
#  endif // !_WIN32
#  include "zephyr-compat.h"
#  include <zephyr/logging/log.h>
#  include "cups.h"
#  ifdef __cplusplus
extern "C" {
#  endif // __cplusplus

//
// This header implements a simple unit test framework for C/C++ programs.
// Inline functions are provided to write a test summary to stdout and the
// details to stderr.  This allows unit test programs to output a summary to
// stdout with details sent to stderr, e.g.:
//
//     mytestprogram 2>test.log
//
// Documentation:
//
// void testBegin(const char *title, ...)
//
//     Start a test with a printf-style title message.  "Title:" (the formatted
//     title followed by a colon) is output.
//
// void testEnd(bool pass)
//
//     End a test without an additional message.  "pass" should be `true` if the
//     test passed and `false` otherwise.  "PASS" or "FAIL" is output.
//
// void testEndMessage(bool pass, const char *message, ...)
//
//     End a test with an additional printf-style message.  "pass" should be
//     `true` if the test passed and `false` otherwise.  "PASS (message)" or
//     "FAIL (message)" is output.
//
// testError(const char *error, ...)
//
//     Sends a formatted error string to stderr.
//
// testHexDump(const unsigned char *buffer, size_t bytes)
//
//     Sends a hex dump of the specified buffer to stderr.
//
// testMessage(const char *error, ...)
//
//     Outputs a formatted message string.
//
// testProgress(void)
//
//     Shows a progress spinner for long-running tests.
//
// bool testsPassed
//
//     This global variable specifies whether all tests have passed (`true`)
//     or one or more have failed (`false`).
//

static bool testsPassed = true;		// All tests passed?
static int test_progress;		// Current progress
static char test_title[1024] = "";	// Current test title


// Start a test
static inline void
testBegin(const char *title, ...)	// I - printf-style title string
{
  LOG_MODULE_DECLARE(libcups);
  va_list	ap;			// Pointer to additional arguments


  // Format the title string
  va_start(ap, title);
  vsnprintfcb(test_title, sizeof(test_title), title, ap);
  va_end(ap);

  // Send the title to stdout and stderr...
  test_progress = 0;

  LOG_INF("%s: \n", test_title);
  // fflush(NULL);
}


// End a test with no additional information
static inline void
testEnd(bool pass)			// I - `true` if the test passed, `false` otherwise
{
  LOG_MODULE_DECLARE(libcups);
  // Send the test result to stdout and stderr
  if (test_progress)
    LOG_INF("\b");

  if (!pass)
    testsPassed = false;

  LOG_INF("%s", pass ? "PASS" : "FAIL");

  test_title[0] = '\0';
}


// End a test with no additional information
static inline void
testEndMessage(bool       pass,		// I - `true` if the test passed, `false` otherwise
               const char *message, ...)// I - printf-style message
{
  LOG_MODULE_DECLARE(libcups);
  char		buffer[1024];		// Formatted title string
  va_list	ap;			// Pointer to additional arguments


  // Format the title string
  va_start(ap, message);
  vsnprintfcb(buffer, sizeof(buffer), message, ap);
  va_end(ap);

  // Send the test result to stdout and stderr
  /* if (test_progress)
    putchar('\b'); */
  if (pass)
    LOG_INF("PASS (%s)\n", buffer);
  else
    LOG_INF("FAIL (%s)\n", buffer);

  test_title[0] = '\0';
}


// Show/update a progress spinner
static inline void
testProgress(void)
{
  LOG_MODULE_DECLARE(libcups);
  if (test_progress)
    LOG_INF("\b");
  char chthing[2];
  chthing[0] = "-\\|/"[test_progress & 3];
  chthing[1] = '\0';
  LOG_INF("%s", chthing);
  // fflush(stdout);

  test_progress ++;
}


// Show an error to stderr...
static inline void
testError(const char *error, ...)	// I - printf-style error string
{
  LOG_MODULE_DECLARE(libcups);
  char		buffer[1024];		// Formatted title string
  va_list	ap;			// Pointer to additional arguments


  // Format the error string
  va_start(ap, error);
  vsnprintfcb(buffer, sizeof(buffer), error, ap);
  va_end(ap);

  // Send the error to stderr...
  LOG_ERR("%s\n", buffer);

  if (test_title[0])
    LOG_ERR("%s: ", test_title);
}


// Show a message to stdout and stderr...
static inline void
testMessage(const char *error, ...)	// I - printf-style error string
{
  LOG_MODULE_DECLARE(libcups);
  char		buffer[1024];		// Formatted title string
  va_list	ap;			// Pointer to additional arguments


  // Format the error string
  va_start(ap, error);
  vsnprintfcb(buffer, sizeof(buffer), error, ap);
  va_end(ap);

  // Send the message to stdout and stderr too if needed...
  LOG_INF("%s\n", buffer);
  if (test_title[0])
  {
    LOG_INF("%s: ", test_title);
    // fflush(stdout);
  }
}


// Show a hex dump of a buffer to stderr...
static inline void
testHexDump(const unsigned char *buffer,// I - Buffer
            size_t              bytes)	// I - Number of bytes
{
  LOG_MODULE_DECLARE(libcups);
  size_t	i, j;			// Looping vars
  int		ch;			// Current ASCII char


  if (test_title[0])
    fputs("\n", stderr);

  // Show lines of 16 bytes at a time...
  for (i = 0; i < bytes; i += 16)
  {
    // Show the offset...
    fprintf(stderr, "%04x ", (unsigned)i);

    // Then up to 16 bytes in hex...
    for (j = 0; j < 16; j ++)
    {
      if ((i + j) < bytes)
        fprintf(stderr, " %02x", buffer[i + j]);
      else
        fputs("   ", stderr);
    }

    // Then the ASCII representation of the bytes...
    fputs("  ", stderr);

    for (j = 0; j < 16 && (i + j) < bytes; j ++)
    {
      ch = buffer[i + j] & 127;

      if (ch < ' ' || ch == 127)
        fputc('.', stderr);
      else
        fputc(ch, stderr);
    }

    fputc('\n', stderr);
  }

  if (test_title[0])
    fprintf(stderr, "%s: ", test_title);
}

#  ifdef __cplusplus
}
#  endif // __cplusplus
#endif // !TEST_H
