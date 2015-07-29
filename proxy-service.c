#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#define HAVE_SECCOMP 1

#define SIZE(x) (sizeof(x)/sizeof(*x))
#define FOR(i, a, b) for (int i = (a); i < (b); i++)
#define REP(i, n) FOR(i, 0, n)
#define EVAL0(...) __VA_ARGS__
#define EVAL1(...) EVAL0 (EVAL0 (EVAL0 (__VA_ARGS__)))
#define EVAL2(...) EVAL1 (EVAL1 (EVAL1 (__VA_ARGS__)))
#define EVAL3(...) EVAL2 (EVAL2 (EVAL2 (__VA_ARGS__)))
#define EVAL4(...) EVAL3 (EVAL3 (EVAL3 (__VA_ARGS__)))
#define EVAL5(...) EVAL4 (EVAL4 (EVAL4 (__VA_ARGS__)))
#define EVAL(...)  EVAL5 (EVAL5 (EVAL5 (__VA_ARGS__)))
#define MAP_END(...)
#define MAP_OUT
#define MAP_GET_END() 0, MAP_END
#define MAP_NEXT0(test, next, ...) next MAP_OUT
#define MAP_NEXT1(test, next) MAP_NEXT0 (test, next)
#define MAP_NEXT(test, next)  MAP_NEXT1 (MAP_GET_END test, next)
#define MAP0(f, x, peek, ...) f(x) MAP_NEXT (peek, MAP1) (f, peek, __VA_ARGS__)
#define MAP1(f, x, peek, ...) f(x) MAP_NEXT (peek, MAP0) (f, peek, __VA_ARGS__)
#define MAP(f, ...) EVAL (MAP1 (f, __VA_ARGS__, ()))

#define LOGDIR_MODE 0700
#define LOGFILE_MODE 0600

enum { BAD_ARG = 1, ERR_PIPE, ERR_FORK, ERR_MKDIR, ERR_CHDIR, ERR_OPEN, ERR_ENV, ERR_SYSCALL, ERR_SOCKET };

#ifdef HAVE_SECCOMP
#include <seccomp.h>
static struct {
  const char *name;
  int num;
  bool allowed;
} syscalls[] = {};

static struct {
  uint32_t action;
  int syscall;
  unsigned arg_cnt;
  struct scmp_arg_cmp arg_array[6];
} scmp_rules[100];
#endif

pid_t child = -1;

int terminate(pid_t child)
{
  int died = 0, status;
  if (kill(child, SIGTERM) != -1) {
    for (int tries = 30; tries > 0; tries--) {
      usleep(100*1000);
      if (waitpid(child, &status, WNOHANG) != -1) {
        died++;
        break;
      }
    }
    if (! died)
      kill(child, SIGKILL);
  }
  return died;
}

int Pipe(int fds[2])
{
  int r = pipe(fds);
  if (r == -1)
    errx(ERR_PIPE, "failed to pipe");
}

pid_t Fork()
{
  int r = fork();
  if (r == -1)
    errx(ERR_FORK, "failed to fork");
  return r;
}

int Chdir(const char *path)
{
  int r = chdir(path);
  if (r == -1) {
    if (child != -1)
      terminate(child);
    errx(ERR_CHDIR, "failed to chdir \"%s\"", path);
  }
  return r;
}

int Mkdir(const char *path, mode_t mode)
{
  int r = mkdir(path, mode);
  if (r == -1) {
    if (child != -1)
      terminate(child);
    errx(ERR_MKDIR, "failed to mkdir \"%s\"", path);
  }
  return r;
}

void sigchld(int _)
{
  //exit(0);
}

struct sockaddr_un unix_p2c, unix_c2p1, unix_c2p2;
bool af_unix = false;
void atexit_rm()
{
  if (af_unix) {
    unlink(unix_p2c.sun_path);
    unlink(unix_c2p1.sun_path);
    unlink(unix_c2p2.sun_path);
  }
}

void show_help(int fd, const char *argv0)
{
#ifdef __i386
  const char *arch = "i386";
#else
# ifdef __x86_64
  const char *arch = "x86_64";
# else
#  ifdef __arm__
  const char *arch = "arm";
#  else
#   ifdef __mips
  const char *arch = "mips";
#   else
#    ifdef __PPC
  const char *arch = "ppc";
#    else
#     error "unknown architecture"
#    endif
#   endif
#  endif
# endif
#endif
  dprintf(fd, "Usage: %s [OPTIONS] ABSOLUTE_PATH\n", basename(argv0));
  dprintf(fd, "Architecture: %s\n", arch);
  dprintf(fd, "\n");
  dprintf(fd, "Options:\n");
  dprintf(fd, "  -a,--abstract\t\t\n");
  dprintf(fd, "  -c SYSCALLS\t\tdisabled syscalls\n");
  dprintf(fd, "  -d,--directory DIR\tlog directory, $LOGDIR/log-#{basename($ABSOLUTE_PATH)}/%%d-%%H:%%M:%%S[.$PID][.(r|w)]\n");
  dprintf(fd, "  -e,--environment ENV\tset env\n");
  dprintf(fd, "  -j,--join\t\tjoin stdout & stderr\n");
  dprintf(fd, "  -o,--policy POLICY\tdef_action, k:KILL, t:TRAP, a:ALLOW(default)\n");
  dprintf(fd, "  -p,--proxy\t\thost:port\n");
  dprintf(fd, "  -s,--separate\t\tseparate log for read & write\n");
}

int main(int argc, char *argv[])
{
  const char *argv0 = argv[0];
  int opt, optidx;

  bool separate_read_write = false;

  bool proxy = false;
  struct sockaddr_in proxy_sin;

  bool join = false;

#ifdef HAVE_SECCOMP
  int nrules = 0;
  uint32_t def_action = SCMP_ACT_ALLOW;
  char *fixed = (char *)mmap((void *)0x800000, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
#endif

  struct option longopts[] = {
    {"abstract"    , no_argument       , 0 , 'a'} ,
    {"directory"   , required_argument , 0 , 'd'} ,
    {"environment" , required_argument , 0 , 'e'} ,
    {"join"        , no_argument       , 0 , 'j'} ,
    {"policy"      , required_argument , 0 , 'o'} ,
    {"proxy"       , required_argument , 0 , 'p'} ,
    {"seccomp"     , required_argument , 0 , 'c'} ,
    {"separate"    , no_argument       , 0 , 's'} ,
    {0             , 0                 , 0 , 0}   ,
  };
  while ((opt = getopt_long(argc, argv, "+0ac:d:e:hjo:p:s", longopts, &optidx)) != -1) {
    switch (opt) {
    case 'a':
      af_unix = true;
      break;
    case 'c': {
#ifdef HAVE_SECCOMP
      char *pp = optarg, *p, *qq, *q, *saved0, *saved1;
      for (; ; pp = NULL) {
        p = strtok_r(pp, " \t,", &saved0);
        if (! p) break;

        bool negative = false;
        int num, pos, nfilters = 0;
        enum scmp_compare op;
        if (nrules >= SIZE(scmp_rules))
          errx(BAD_ARG, "too many rules");
        if (*p == '+')
          p++;
        else if (*p == '-')
          p++, negative = true;
        scmp_rules[nrules].action = negative ? SCMP_ACT_TRAP : SCMP_ACT_ALLOW;

        for (qq = p; ; qq = NULL) {
          q = strtok_r(qq, ":", &saved1);
          if (! q) break;
          if (qq) {
            num = seccomp_syscall_resolve_name(q);
            if (num < 0)
              errx(BAD_ARG, "unknown syscall \"%s\"", q);
            scmp_rules[nrules].syscall = num;
          } else {
            if (nfilters >= SIZE(scmp_rules[0].arg_array))
              errx(BAD_ARG, "too many filters");
            if (! ('0' <= *q && *q <= '5'))
              errx(BAD_ARG, "argument position should be 0-5");
            pos = *q-'0';
            REP(i, nfilters)
              if (pos == scmp_rules[nrules].arg_array[i].arg)
                errx(BAD_ARG, "duplicate argument position %d", pos);
            q++;
            if (*q == '=')
              q++, op = SCMP_CMP_EQ;
            else if (*q == '!' && q[1] == '=')
              q += 2, op = SCMP_CMP_NE;
            else if (*q == '<') {
              if (q[1] == '=')
                q += 2, op = SCMP_CMP_LE;
              else
                q++, op = SCMP_CMP_LT;
            } else if (*q == '>') {
              if (q[1] == '=')
                q += 2, op = SCMP_CMP_GE;
              else
                q++, op = SCMP_CMP_GT;
            }
            else
              errx(BAD_ARG, "unknown operator \"%c\"", *q);
            scmp_datum_t val = strtol(q, &q, 0);
            if (*q)
              errx(BAD_ARG, "invalid number");
            scmp_rules[nrules].arg_array[nfilters++] = SCMP_CMP(pos, op, val);
          }
        }
        scmp_rules[nrules].arg_cnt = nfilters;
        nrules++;
      }
#else
      errx(ERR_SYSCALL, "HAVE_SECCOMP not enabled");
#endif
      break;
    }
    case 'd':
      Chdir(optarg);
      break;
    case 'h':
      show_help(STDOUT_FILENO, argv0);
      break;
    case 'j':
      join = true;
      break;
    case 'e':
      putenv(optarg);
      break;
    case 'o':
#ifdef HAVE_SECCOMP
      if (optarg[0] == 'k')
        def_action = SCMP_ACT_KILL;
      else if (optarg[0] == 't')
        def_action = SCMP_ACT_TRAP;
      else if (optarg[0] == 'a')
        def_action = SCMP_ACT_ALLOW;
#else
      errx(ERR_SYSCALL, "HAVE_SECCOMP not enabled");
#endif
      break;
    case 'p': // proxy
      {
        char *p = strchr(optarg, ':');
        if (! p)
          errx(BAD_ARG, "no semicolon");
        *p = '\0';
        proxy_sin.sin_family = AF_INET;
        if (inet_aton(optarg, &proxy_sin.sin_addr) < 0)
          errx(BAD_ARG, "gethostbyname: %s", strerror(errno));
        proxy_sin.sin_port = htons(strtol(p+1, &p, 10));
        if (*p)
          errx(BAD_ARG, "port");
        proxy = true;
      }
      break;
    case 's':
      separate_read_write = true;
      break;
    default:
      show_help(STDERR_FILENO, argv0);
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc < 1) {
    show_help(STDERR_FILENO, argv0);
    return BAD_ARG;
  }

  char buf[4096];
  int pipe_p2c[2], pipe_c2p1[2], pipe_c2p2[2];
  if (af_unix) {
    unix_p2c.sun_family = AF_UNIX; 
    unix_c2p1.sun_family = AF_UNIX;
    unix_c2p2.sun_family = AF_UNIX;
    unix_p2c.sun_path[0] = '\0';
    unix_c2p1.sun_path[0] = '\0';
    unix_c2p2.sun_path[0] = '\0';
    sprintf(unix_p2c.sun_path+1, "/tmp/unix/%d-%d.in", getuid(), getpid());
    sprintf(unix_c2p1.sun_path+1, "/tmp/unix/%d-%d.out", getuid(), getpid());
    sprintf(unix_c2p2.sun_path+1, "/tmp/unix/%d-%d.err", getuid(), getpid());
    pipe_p2c[0] = socket(AF_UNIX, SOCK_STREAM, 0);
    pipe_c2p1[1] = socket(AF_UNIX, SOCK_STREAM, 0);
    if (! join)
      pipe_c2p2[1] = socket(AF_UNIX, SOCK_STREAM, 0);
    atexit(atexit_rm);
    if (bind(pipe_p2c[0], &unix_p2c, sizeof unix_p2c) < 0 ||
        bind(pipe_c2p1[1], &unix_c2p1, sizeof unix_c2p1) < 0)
      return perror(""), 0;
    if (! join && bind(pipe_c2p2[1], &unix_c2p2, sizeof unix_c2p2) < 0)
      return perror(""), 0;
    if (listen(pipe_p2c[0], 1) < 0 ||
        listen(pipe_c2p1[1], 1) < 0)
      return perror(""), 0;
    if (! join && listen(pipe_c2p2[1], 1) < 0)
      return perror(""), 0;
  } else {
    Pipe(pipe_p2c);
    Pipe(pipe_c2p1);
    if (! join)
      Pipe(pipe_c2p2);
  }

  child = Fork();
  if (! child) {
    // child
    if (af_unix) {
      // close bound sockets
      close(pipe_p2c[0]);
      close(pipe_c2p1[1]);
      close(pipe_c2p2[1]);

      // domain sockets for client
      pipe_p2c[1] = socket(AF_UNIX, SOCK_STREAM, 0);
      pipe_c2p1[0] = socket(AF_UNIX, SOCK_STREAM, 0);
      if (! join)
        pipe_c2p2[0] = socket(AF_UNIX, SOCK_STREAM, 0);

      if (connect(pipe_p2c[1], &unix_p2c, sizeof unix_p2c) < 0 ||
          connect(pipe_c2p1[0], &unix_c2p1, sizeof unix_c2p1) < 0)
        return 0;
      dup2(pipe_p2c[1], STDIN_FILENO); close(pipe_p2c[1]);
      dup2(pipe_c2p1[0], STDOUT_FILENO); close(pipe_c2p1[0]);
      if (join)
        dup2(STDOUT_FILENO, STDERR_FILENO);
      else {
        connect(pipe_c2p2[0], &unix_c2p2, sizeof unix_c2p2);
        dup2(pipe_c2p2[0], STDERR_FILENO); close(pipe_c2p2[0]);
      }
    } else {
      close(pipe_p2c[1]); dup2(pipe_p2c[0], STDIN_FILENO); close(pipe_p2c[0]);
      close(pipe_c2p1[0]); dup2(pipe_c2p1[1], STDOUT_FILENO); close(pipe_c2p1[1]);
      if (join)
        dup2(STDOUT_FILENO, STDERR_FILENO);
      else {
        close(pipe_c2p2[0]); dup2(pipe_c2p2[1], STDERR_FILENO); close(pipe_c2p2[1]);
      }
    }

#ifdef HAVE_SECCOMP
    scmp_filter_ctx ctx = seccomp_init(def_action);
    if (ctx == NULL)
      return 1;
    REP(i, nrules) {
      int ret = seccomp_rule_add_array(ctx, scmp_rules[i].action, scmp_rules[i].syscall,
                                       scmp_rules[i].arg_cnt, scmp_rules[i].arg_array);
      if (ret < 0)
        return 1;
    }
    if (seccomp_load(ctx) < 0)
      return 1;
    seccomp_release(ctx);

    strcpy(fixed, *argv);
    execv(fixed, argv); // execve will change the first argument
#else
    execvp(*argv, argv);
#endif
  } else {
    // parent
    //signal(SIGCHLD, sigchld);
    if (af_unix) {
      socklen_t unix_p2clen, unix_c2p1len, unix_c2p2len;
      if ((pipe_p2c[1] = accept(pipe_p2c[0], &unix_p2c, &unix_p2clen)) < 0 ||
          (pipe_c2p1[0] = accept(pipe_c2p1[1], &unix_c2p1, &unix_c2p1len)) < 0)
        return 0;
      if (! join && (pipe_c2p2[0] = accept(pipe_c2p2[1], &unix_c2p2, &unix_c2p2len)) < 0)
        return 0;
      close(pipe_p2c[0]);
      close(pipe_c2p1[1]);
      if (! join)
        close(pipe_c2p2[1]);
    } else {
      close(pipe_p2c[0]);
      close(pipe_c2p1[1]);
      if (! join)
        close(pipe_c2p2[1]);
    }

    struct stat statbuf;
    snprintf(buf, sizeof buf, "log-%s", basename(argv[0]));
    if (stat(buf, &statbuf) == -1 && errno == ENOENT)
      Mkdir(buf, LOGDIR_MODE);
    Chdir(buf);

    int log_r, log_w, log_err;
    time_t now = time(NULL);
    struct tm tim = *localtime(&now);
    strftime(buf, sizeof buf, "%d-%H:%M:%S", &tim);
    {
      pid_t pid = getpid();
      sprintf(buf+strlen(buf), ".%d", pid);
    }
    if (separate_read_write) {
      strcat(buf, ".r");
      log_r = open(buf, O_WRONLY | O_CREAT | O_EXCL, LOGFILE_MODE);
      buf[strlen(buf)-1] = 'w';
      log_w = open(buf, O_WRONLY | O_CREAT | O_EXCL, LOGFILE_MODE);
      if (! join) {
        strcpy(buf+strlen(buf)-1, "log");
        log_err = open(buf, O_WRONLY | O_CREAT | O_EXCL, LOGFILE_MODE);
      }
    } else {
      log_w = log_r = open(buf, O_WRONLY | O_CREAT, LOGFILE_MODE);
      if (! join) {
        strcat(buf, ".log");
        log_err = open(buf, O_WRONLY | O_CREAT | O_EXCL, LOGFILE_MODE);
      }
    }
    if (! join && log_err == -1)
      errx(ERR_OPEN, "failed to create \"%s\"", buf);
    if (log_w == -1)
      errx(ERR_OPEN, "failed to create \"%s\"", buf);
    if (log_r == -1 && separate_read_write) {
      buf[strlen(buf)-1] = 'r';
      errx(ERR_OPEN, "failed to create \"%s\"", buf);
    }

    int sockfd;
    if (proxy) {
      sockfd = socket(AF_INET, SOCK_STREAM, 0);
      if (sockfd < 0)
        errx(ERR_SOCKET, "socket: %s", strerror(errno));
      if (connect(sockfd, (struct sockaddr *)&proxy_sin, sizeof proxy_sin) < 0)
        errx(ERR_SOCKET, "connect: %s", strerror(errno));
      dup2(sockfd, STDIN_FILENO);
      dup2(sockfd, STDOUT_FILENO);
      //dup2(sockfd, STDERR_FILENO);
      close(sockfd);
    }

    fd_set rfds;
    for(;;) {
      int maxfd = -1;
      FD_ZERO(&rfds);
      if (fcntl(STDIN_FILENO, F_GETFD) != -1) {
        FD_SET(STDIN_FILENO, &rfds);
        maxfd = STDIN_FILENO;
      }
      if (fcntl(pipe_c2p1[0], F_GETFD) != -1) {
        FD_SET(pipe_c2p1[0], &rfds);
        if (pipe_c2p1[0] > maxfd)
          maxfd = pipe_c2p1[0];
      }
      if (! join && fcntl(pipe_c2p2[0], F_GETFD) != -1) {
        FD_SET(pipe_c2p2[0], &rfds);
        if (pipe_c2p2[0] > maxfd)
          maxfd = pipe_c2p2[0];
      }
      if (maxfd < 0 || select(maxfd+1, &rfds, NULL, NULL, NULL) <= 0)
        break;
      if (FD_ISSET(pipe_c2p1[0], &rfds)) {
        ssize_t nbuf = read(pipe_c2p1[0], buf, sizeof buf);
        if (nbuf <= 0) {
          close(pipe_c2p1[0]);
          close(STDOUT_FILENO);
          break;
        } else {
          write(log_w, buf, nbuf);
          if (write(STDOUT_FILENO, buf, nbuf) != nbuf)
            break;
        }
      }
      if (! join && FD_ISSET(pipe_c2p2[0], &rfds)) {
        ssize_t nbuf = read(pipe_c2p2[0], buf, sizeof buf);
        if (nbuf <= 0) {
          close(pipe_c2p2[0]);
          close(STDERR_FILENO);
          break;
        } else {
          write(log_err, buf, nbuf);
          if (write(STDERR_FILENO, buf, nbuf) != nbuf)
            break;
        }
      }
      if (FD_ISSET(STDIN_FILENO, &rfds)) {
        ssize_t nbuf = read(STDIN_FILENO, buf, sizeof buf);
        if (nbuf <= 0) {
          close(STDIN_FILENO);
          close(pipe_p2c[1]);
        } else {
          write(log_r, buf, nbuf);
          if (write(pipe_p2c[1], buf, nbuf) != nbuf)
            break;
        }
      }
    }
    close(log_r);
    close(log_w);
    if (! join)
      close(log_err);
    terminate(child);
  }

  return 0;
}
