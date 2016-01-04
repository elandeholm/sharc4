#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>
#include "rawtty.h"

/* reads an unbuffered character from tty */

int tty_readch(ttystruct_t *ttys, unsigned char *ch)
{
  int n;

  *ch = '\0';
  n = read(ttys->fd, ch, 1);
  if(n != 1)
    return -1;
  else
    return 0;
}

/* open unbuffered tty, noecho */

int init_tty(ttystruct_t *ttys)
{
  struct termios newtty;
  int status;

  status = 0;

  ttys->fp = fopen("/dev/tty", "rb");

  if(ttys->fp)
    {
      ttys->fd = fileno(ttys->fp);
      ioctl(ttys->fd, TIOCGETA, &ttys->savetty);
      ioctl(ttys->fd, TIOCGETA, &newtty);
      newtty.c_lflag &= ~ICANON;
      newtty.c_lflag &= ~ECHO;
      ioctl(ttys->fd, TIOCSETAF, &newtty);
    }
  else
    status = -1;

  return status;
}

/* reset tty to saved state, close file */

void reset_tty(ttystruct_t *ttys)
{
  if(ttys->fp)
    {
      ioctl(ttys->fd, TIOCSETAF, &ttys->savetty);
      fclose(ttys->fp);      
    }
}
