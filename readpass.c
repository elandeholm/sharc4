#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <stdio.h>
#include "sha256.h" /* provides uint8 */
#include "rawtty.h"
#include "readpass.h"

/* reads password, char by char, from tty
 * returns the number of characters read
 * handles delete/backspace
 */

static int _readpass(ttystruct_t *ttys, uint8 *pass, int plen)
{
  int c;
  int ptr;

  ptr = 0;

  while((c = fgetc(ttys->fp)) != EOF)
    {
      if(c == '\n' || c == '\r')
	break;
      if(c == 8 || c == 127) /* delete/backspace */
	{
	  if(ptr > 0)
	    {
	      --ptr;
	      pass[ptr] = '\0';
	    }
	  else
	    fprintf(stderr, "\a");
	}
      else if(ptr == plen)
	{
	  fprintf(stderr, "\a");
	}
      else
	{
	  pass[ptr] = c;
	  ++ptr;
	}
    }

  return ptr;
}

/* read password from raw tty,
 * return number of characters read or -1 on error
 */

int readpass(const char *prompt, uint8 *pass, int plen)
{
  ttystruct_t ttys;
  int status;

  memset(pass, 0, plen);

  status = init_tty(&ttys);

  if(status != -1)
    {
      fprintf(stderr, "%s", prompt);
      status = _readpass(&ttys, pass, plen);
      reset_tty(&ttys);
    }
  else
    status = -1;

  return status;
}
