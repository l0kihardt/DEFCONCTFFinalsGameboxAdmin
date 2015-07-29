#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <execinfo.h>
#include <stdarg.h>
#include <sys/select.h>
#include <getopt.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#define FOR(i, a, b) for (int i = (a); i < (b); i++)
#define REP(i, n) FOR(i, 0, n)
#define SIZE(a) (sizeof(a)/sizeof(*a))

#define SGR0 "\x1b[m"
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"

#define BUF_SIZE 1024
#define FLAG_NAME "flag"
#define FLAG_BUFSIZE 1213
#define ACCESS_COOLDOWN_SECOND 5
#define IS_FLAG_CHAR(c) (isalnum(c) || (c) == '-')
#define SEND_TIMEOUT_MILLI 100

///// log

void log_generic(const char *prefix, const char *format, va_list ap)
{
  char buf[BUF_SIZE];
  struct timeval tv;
  struct tm tm;
  gettimeofday(&tv, NULL);
  fputs(prefix, stdout);
  if (localtime_r(&tv.tv_sec, &tm)) {
    strftime(buf, sizeof buf, "%T.%%06u ", &tm);
    printf(buf, tv.tv_usec);
  }
  vprintf(format, ap);
  fputs(SGR0, stdout);
  fflush(stdout);
}

void log_event(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  log_generic(CYAN, format, ap);
  va_end(ap);
}

void log_action(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  log_generic(GREEN, format, ap);
  va_end(ap);
}

void log_status(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  log_generic(YELLOW, format, ap);
  va_end(ap);
}

///// error

static const char *ENAME[] = {
    /*   0 */ "",
    /*   1 */ "EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO",
    /*   7 */ "E2BIG", "ENOEXEC", "EBADF", "ECHILD",
    /*  11 */ "EAGAIN/EWOULDBLOCK", "ENOMEM", "EACCES", "EFAULT",
    /*  15 */ "ENOTBLK", "EBUSY", "EEXIST", "EXDEV", "ENODEV",
    /*  20 */ "ENOTDIR", "EISDIR", "EINVAL", "ENFILE", "EMFILE",
    /*  25 */ "ENOTTY", "ETXTBSY", "EFBIG", "ENOSPC", "ESPIPE",
    /*  30 */ "EROFS", "EMLINK", "EPIPE", "EDOM", "ERANGE",
    /*  35 */ "EDEADLK/EDEADLOCK", "ENAMETOOLONG", "ENOLCK", "ENOSYS",
    /*  39 */ "ENOTEMPTY", "ELOOP", "", "ENOMSG", "EIDRM", "ECHRNG",
    /*  45 */ "EL2NSYNC", "EL3HLT", "EL3RST", "ELNRNG", "EUNATCH",
    /*  50 */ "ENOCSI", "EL2HLT", "EBADE", "EBADR", "EXFULL", "ENOANO",
    /*  56 */ "EBADRQC", "EBADSLT", "", "EBFONT", "ENOSTR", "ENODATA",
    /*  62 */ "ETIME", "ENOSR", "ENONET", "ENOPKG", "EREMOTE",
    /*  67 */ "ENOLINK", "EADV", "ESRMNT", "ECOMM", "EPROTO",
    /*  72 */ "EMULTIHOP", "EDOTDOT", "EBADMSG", "EOVERFLOW",
    /*  76 */ "ENOTUNIQ", "EBADFD", "EREMCHG", "ELIBACC", "ELIBBAD",
    /*  81 */ "ELIBSCN", "ELIBMAX", "ELIBEXEC", "EILSEQ", "ERESTART",
    /*  86 */ "ESTRPIPE", "EUSERS", "ENOTSOCK", "EDESTADDRREQ",
    /*  90 */ "EMSGSIZE", "EPROTOTYPE", "ENOPROTOOPT",
    /*  93 */ "EPROTONOSUPPORT", "ESOCKTNOSUPPORT",
    /*  95 */ "EOPNOTSUPP/ENOTSUP", "EPFNOSUPPORT", "EAFNOSUPPORT",
    /*  98 */ "EADDRINUSE", "EADDRNOTAVAIL", "ENETDOWN", "ENETUNREACH",
    /* 102 */ "ENETRESET", "ECONNABORTED", "ECONNRESET", "ENOBUFS",
    /* 106 */ "EISCONN", "ENOTCONN", "ESHUTDOWN", "ETOOMANYREFS",
    /* 110 */ "ETIMEDOUT", "ECONNREFUSED", "EHOSTDOWN", "EHOSTUNREACH",
    /* 114 */ "EALREADY", "EINPROGRESS", "ESTALE", "EUCLEAN",
    /* 118 */ "ENOTNAM", "ENAVAIL", "EISNAM", "EREMOTEIO", "EDQUOT",
    /* 123 */ "ENOMEDIUM", "EMEDIUMTYPE", "ECANCELED", "ENOKEY",
    /* 127 */ "EKEYEXPIRED", "EKEYREVOKED", "EKEYREJECTED",
    /* 130 */ "EOWNERDEAD", "ENOTRECOVERABLE", "ERFKILL", "EHWPOISON"
};

#define MAX_ENAME 133

void output_error(bool use_err, const char *format, va_list ap)
{
  char text[BUF_SIZE], msg[BUF_SIZE], buf[BUF_SIZE];
  vsnprintf(msg, BUF_SIZE, format, ap);
  if (use_err)
    snprintf(text, BUF_SIZE, "[%s %s] ", 0 < errno && errno < MAX_ENAME ? ENAME[errno] : "?UNKNOWN?", strerror(errno));
  else
    strcpy(text, "");
  snprintf(buf, BUF_SIZE, RED "%s%s\n", text, msg);
  fputs(buf, stderr);
  fputs(SGR0, stderr);
  fflush(stderr);
}

void err_msg(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  int saved = errno;
  output_error(errno > 0, format, ap);
  errno = saved;
  va_end(ap);
}

void err_exit(int exitno, const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  int saved = errno;
  output_error(errno > 0, format, ap);
  errno = saved;
  va_end(ap);

  void *bt[99];
  char buf[1024];
  int nptrs = backtrace(bt, SIZE(buf));
  int i = sprintf(buf, "addr2line -Cfipe %s", program_invocation_name), j = 0;
  while (j < nptrs && i+30 < sizeof buf)
    i += sprintf(buf+i, " %#x", bt[j++]);
  strcat(buf, ">&2");
  fputs("\n", stderr);
  system(buf);
  //backtrace_symbols_fd(buf, nptrs, STDERR_FILENO);
  exit(exitno);
}

///// common

int get_int(const char *arg)
{
  char *end;
  errno = 0;
  long ret = strtol(arg, &end, 0);
  if (errno)
    err_exit(EX_USAGE, "get_int: %s", arg);
  if (*end)
    err_exit(EX_USAGE, "get_int: nonnumeric character");
  if (ret < INT_MIN || INT_MAX < ret)
    err_exit(EX_USAGE, "get_int: out of range");
  return ret;
}

///// usage

__attribute__((noreturn))
void print_usage(FILE *fh)
{
  exit(fh == stdout ? 0 : EX_USAGE);
}

char *notify_host = NULL;
int notify_port;

int nwatched = 0;
struct Watch
{
  int wd;
  char *path, *service;
  mode_t mode;
  int free_read, free_write;
  double last_access;
} watched[1024];

bool is_flag(const char *name)
{
  return ! strcmp(name, FLAG_NAME);
}

struct Watch *new_watch(void)
{
  int i;
  for (i = 0; i < SIZE(watched); i++)
    if (watched[i].wd < 0)
      break;
  if (i == SIZE(watched)) {
    if (nwatched >= SIZE(watched))
      err_exit(EX_UNAVAILABLE, "too many watch descriptors");
    i = nwatched++;
  }
  watched[i].service = NULL;
  watched[i].free_read = 0;
  watched[i].free_write = 0;
  watched[i].last_access = 0.0;
  return &watched[i];
}

void rm_watch(int inotify_fd, struct Watch *watch)
{
  if (inotify_rm_watch(inotify_fd, watch->wd) < 0)
    err_exit(EX_OSERR, "inotify_rm_watch %s", watch->path);
  free(watch->path);
  if (watch->service)
    free(watch->service);
  watch->wd = -1;
}

void add_inotify_flag(int inotify_fd, const struct inotify_event *ev, const struct Watch *watch)
{
  struct Watch *new_w = new_watch();
  if (asprintf(&new_w->path, "%s/%s", watch->path, ev->name) < 0)
    err_exit(EX_OSERR, "asprintf");
  if (! (new_w->service = strdup(strrchr(watch->path, '/')+1)))
    err_exit(EX_OSERR, "strdup");
  if ((new_w->wd = inotify_add_watch(inotify_fd, new_w->path, IN_ACCESS)) < 0)
    err_exit(EX_OSERR, "inotify_add_watch");
  log_action("created ACCESS inotify %s\n", new_w->path);
}

void rm_inotify_flag(int inotify_fd, const struct inotify_event *ev, const struct Watch *watch)
{
  const char *service = strrchr(watch->path, '/')+1;
  REP(i, nwatched)
    if (watched[i].wd >= 0 && watched[i].service && ! strcmp(watched[i].service, service)) {
      log_status("removing ACCESS inotify %s\n", watched[i].path);
      rm_watch(inotify_fd, &watched[i]);
    }
}

void notify(const char *format, ...)
{
  if (! notify_host) return;

  char *buf;
  int len, nwrite = 0;
  va_list ap;
  va_start(ap, format);
  if ((len = vasprintf(&buf, format, ap)) < 0)
    err_exit(EX_OSERR, "vasprintf");
  va_end(ap);
  log_action("notify %s", buf);

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  if (inet_aton(notify_host, &sin.sin_addr) < 0) {
    err_msg("inet_aton");
    goto quit;
  }
  sin.sin_port = htons(notify_port);

  int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (sockfd < 0) {
    err_msg("socket");
    goto quit;
  }

  bool connected = false;
  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(sockfd, &wfds);
  struct timeval timeout = {.tv_sec=SEND_TIMEOUT_MILLI/1000, .tv_usec=SEND_TIMEOUT_MILLI%1000*1000};
  while (nwrite < len) {
    int res = select(sockfd+1, NULL, &wfds, NULL, &timeout); // Linux modifies timeout
    if (res < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (! res) {
      err_msg("timeout to notify");
      goto quit;
    }
    if (! connected) {
      res = connect(sockfd, (struct sockaddr *)&sin, sizeof sin);
      if (res < 0) {
        if (errno == EINTR || errno == EINPROGRESS) continue;
        err_msg("connect");
        goto quit;
      }
      connected = true;
    } else {
      res = write(sockfd, buf+nwrite, len-nwrite);
      if (res < 0) {
        err_msg("write");
        goto quit;
      }
      nwrite += res;
    }
  }

quit:
  if (sockfd >= 0)
    close(sockfd);
  free(buf);
}

void new_flag(struct Watch *watch)
{
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) < 0)
    err_exit(EX_OSERR, "clock_gettime");
  char flag[FLAG_BUFSIZE], path[PATH_MAX];
  snprintf(path, sizeof path, "%s/%s", watch->path, FLAG_NAME);
  int fd = open(path, O_RDONLY), nread;
  if (fd < 0) {
    err_msg("open %s", watch->path);
    goto quit;
  }
  if ((nread = read(fd, flag, sizeof flag - 1)) < 0) {
    err_msg("failed to read flag file %s", watch->path);
    goto quit;
  }
  watch->free_read++;
  int i;
  for (i = 0; i < nread; i++)
    if (! IS_FLAG_CHAR(flag[i]))
      break;
  if (i) {
    const char *service = strrchr(watch->path, '/')+1;
    flag[i] = '\0';
    notify("{\"event\":\"new\",\"timestamp\":%ld.%09ld,\"service\":\"%s\",\"flag\":\"%s\"\n", (long)now.tv_sec, now.tv_nsec, service, flag);
  }

quit:
  if (fd >= 0)
    close(fd);
}

void do_access(struct Watch *watch)
{
  const char *service = strrchr(watch->path, '/')+1;
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) < 0)
    err_exit(EX_OSERR, "clock_gettime");
  double nowd = now.tv_sec + now.tv_nsec * 1e-9;
  if (nowd - watch->last_access >= ACCESS_COOLDOWN_SECOND) {
    notify("{\"event\":\"access\",\"timestamp\":%ld.%09ld,\"service\":\"%s\"\n", (long)now.tv_sec, now.tv_nsec, service);
    watch->last_access = nowd;
  }
}

int main(int argc, char *argv[])
{
  char path[PATH_MAX];
  int opt, event_count = -1;
  static struct option long_options[] = {
    {"count",               required_argument, 0,   'c'},
    {"help",                no_argument,       0,   'h'},
    {"notify",              required_argument, 0,   'n'},
    {0,                     0,                 0,   0},
  };

  int inotify_fd = inotify_init();
  if (inotify_fd < 0)
    err_exit(EX_OSERR, "inotify_init");

  while ((opt = getopt_long(argc, argv, "-c:hn:", long_options, NULL)) != -1) {
    switch (opt) {
    case 1: {
      struct Watch *watch = new_watch();
      if (realpath(optarg, path) < 0)
        err_exit(EX_OSFILE, "realpath");
      watch->path = strdup(path);
      struct stat statbuf;
      if (stat(optarg, &statbuf) < 0)
        err_exit(EX_OSFILE, "stat");
      if (! (statbuf.st_mode & S_IFDIR))
        err_exit(EX_OSFILE, "not directory");
      watch->mode = statbuf.st_mode;
      if ((watch->wd = inotify_add_watch(inotify_fd, optarg, IN_ACCESS | IN_CREATE | IN_CLOSE_WRITE | IN_DELETE | IN_MODIFY | IN_MOVE)) < 0)
        err_exit(EX_OSERR, "inotify_add_watch");
      break;
    }
    case 'c':
      event_count = get_int(optarg);
      break;
    case 'h':
      print_usage(stdout);
      break;
    case 'n': {
      if (notify_host)
        err_exit(EX_USAGE, "cannot specify multiple hosts");
      notify_host = optarg;
      char *p = strchr(notify_host, ':');
      if (! p)
        err_exit(EX_USAGE, "no port specified");
      *p = '\0';
      notify_port = get_int(p+1);
      break;
    }
    case '?':
      print_usage(stderr);
      break;
    }
  }

  if (! nwatched)
    err_exit(EX_USAGE, "no directory specified to watch");

  while (event_count) {
    char buf[sizeof(struct inotify_event)+NAME_MAX+1];
    int nread;
    if ((nread = read(inotify_fd, buf, sizeof buf)) <= 0)
      err_exit(EX_OSERR, "failed to read inotify fd");
    for (struct inotify_event *ev = (struct inotify_event *)buf; (char *)ev < (char *)buf+nread && event_count;
        ev = (struct inotify_event *)((char *)ev + sizeof(struct inotify_event) + ev->len))
      if (ev->len > 0) {
        struct Watch *watch = NULL;
        REP(i, nwatched)
          if (watched[i].wd == ev->wd) {
            watch = &watched[i];
            break;
          }
        if (ev->mask & IN_ACCESS) {
          if (watch->free_read > 0)
            watch->free_read--;
          else {
            log_event("ACCESS %s\n", ev->name);
            do_access(watch);
          }
        } else if (ev->mask & IN_CLOSE_WRITE) {
          log_event("CLOSE_WRITE %s\n", ev->name);
          if (is_flag(ev->name))
            new_flag(watch);
        } else if (ev->mask & IN_CREATE) {
          log_event("CREATE %s\n", ev->name);
          if (is_flag(ev->name)) {
            add_inotify_flag(inotify_fd, ev, watch);
            struct stat statbuf;
            char *path;
            if (asprintf(&path, "%s/%s", watch->path, FLAG_NAME) < 0)
              err_exit(EX_OSERR, "asprintf");
            if (lstat(path, &statbuf) < 0)
              err_msg("lstat");
            else if (S_IFLNK & statbuf.st_mode)
              new_flag(watch);
            free(path);
          }
        } else if (ev->mask & IN_DELETE) {
          log_event("DELETE %s\n", ev->name);
          if (is_flag(ev->name))
            rm_inotify_flag(inotify_fd, ev, watch);
        } else if (ev->mask & IN_MOVED_FROM) {
          log_event("MOVED_FROM %s\n", ev->name);
          if (is_flag(ev->name))
            rm_inotify_flag(inotify_fd, ev, watch);
        } else if (ev->mask & IN_MOVED_TO) {
          log_event("MOVED_TO %s\n", ev->name);
          if (is_flag(ev->name)) {
            add_inotify_flag(inotify_fd, ev, watch);
            new_flag(watch);
          }
        }
        event_count > 0 && event_count--;
      }
  }

  REP(i, nwatched)
    if (watched[i].wd >= 0)
      rm_watch(inotify_fd, &watched[i]);
  close(inotify_fd);
}
