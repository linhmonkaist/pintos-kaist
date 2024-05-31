/* -*- c -*- */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

static char buf[TEST_SIZE];

void
test_main (void) 
{
  const char *file_name = "blargle";
  // timeout here !!
  // PANIC("error here");
  CHECK (create (file_name, TEST_SIZE), "create \"%s\"", file_name);
  //couldn't pass here
//  PANIC("error here");
  check_file (file_name, buf, TEST_SIZE);
  //couldn't pass here
  // PANIC("error here");
}
