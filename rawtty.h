typedef struct
{
  struct termios savetty;
  FILE *fp;
  int fd;  
} ttystruct_t;

int tty_readch(ttystruct_t *ttys, unsigned char *ch);
int init_tty(ttystruct_t *ttys);
void reset_tty(ttystruct_t *ttys);
