#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <functional>
#include <getopt.h>
#include <stdarg.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sysexits.h>
#include <time.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>
using namespace std;

#define SIZE(a) (sizeof(a)/sizeof(*a))
#define REP(i, n) FOR(i, 0, n)
#define FOR(i, a, b) for (typename std::remove_cv<typename std::remove_reference<decltype(b)>::type>::type i = (a); i < (b); i++)
#define ROF(i, a, b) for (typename std::remove_cv<typename std::remove_reference<decltype(b)>::type>::type i = (b); --i >= (a); )

#define SGR0 "\x1b[m"
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

const double FLAG_DURATION = 5*60; // 5 minutes
const int BUF_SIZE = 1024;
const char PATTERN_SEPARATOR[] = " \t,|";
const char *PCAPNG_SUFFIXES[] = {".cap", ".pcap", ".pcapng"};

///// log

void log_generic(const char *prefix, const char *format, va_list ap)
{
  char buf[BUF_SIZE];
  timeval tv;
  tm tm;
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

class StopWatch
{
  timeval start_;
public:
  StopWatch() { gettimeofday(&start_, NULL); }
  double elapsed() {
    timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec-start_.tv_sec)+(now.tv_usec-start_.tv_usec)*1e-6;
  }
};

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
#define err_msg_g(...) ({err_msg(__VA_ARGS__); goto quit;})

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

double get_double(const char *arg)
{
  char *end;
  errno = 0;
  double ret = strtod(arg, &end);
  if (errno)
    err_exit(EX_USAGE, "get_double: %s", arg);
  if (*end)
    err_exit(EX_USAGE, "get_double: nonnumeric character");
  return ret;
}

void print_usage(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS] dir\n", program_invocation_short_name);
  fputs(
        "\n"
        "Options:\n"
        "  -b, --byte-offset        print the byte offset with output lines\n"
        "  -c, --count              print only a count of matching lines per FILE\n"
        "  -f, --file=FILE          obtain flags from FILE, one per line\n"
        "                           1 field: $FLAG . timestamp is omitted, each matching packet is displayed\n"
        "                           3 fields: $EPOCH $SERVICE $FLAG . packets out of [$EPOCH, $EPOCH+FLAG_DURATION) are ignored\n"
        "  -H, --with-frame-number  print frame.number\n"
        "  -h, --help               display this help text and exit\n"
        "  -r, --recursive          recursive\n"
        "  -v, --verbose            verbose mode\n"
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

bool opt_verbose = false;
bool opt_count = false;
bool opt_offset = false;
bool opt_frame_number = false;
bool opt_recursive = false;
int length = 0;

namespace MultiBackwardDAWG
{
int tail;
struct Node
{
  int l = 0, f = 0, c[256], id = -1;
  Node() { memset(&c, 0, sizeof c); }
};
vector<Node> g;

void init()
{
  g.clear();
  g.resize(2);
}

void extend(int c)
{
  int p = tail, q, r, x = g.size();
  g.resize(x+1);
  g[x].l = g[tail].l + 1;
  for (; p && ! g[p].c[c]; p = g[p].f)
    g[p].c[c] = x;
  if (! p)
    g[x].f = 1;
  else if (g[p].l + g[q = g[p].c[c]].l)
    g[x].f = q;
  else {
    r = g.size();
    g.resize(r+1);
    g[r] = g[q];
    g[r].l = g[p].l + 1;
    g[x].f = g[q].f = r;
    for (; p && g[p].c[c] == q; p = g[p].f)
      g[p].c[c] = r;
  }
  tail = x;
}

void add(int len, const char *s)
{
  tail = 1;
  ROF(i, 0, len)
    extend((u8)s[i]);
}

void mark(int id, int len, const char *s)
{
  int x = 1;
  ROF(i, 0, len)
    x = g[x].c[(u8)s[i]];
  for (; x; x = g[x].f)
    g[x].id = id;
}

void search(int len, const u8 *haystack, const function<void(int, int)> &fn)
{
  int x, y, j, shift, period;
  for (int i = 0; i <= len-length; i += shift) {
    x = 1;
    shift = length;
    j = length-1;
    for (; j >= 0 && (y = g[x].c[haystack[i+j]]); j--) {
      x = y;
      if (g[x].id >= 0) {
        period = shift;
        shift = j;
      }
    }
    if (j < 0) {
      fn(g[x].id, i);
      shift = period;
    }
  }
}
};

struct Flag
{
  double timestamp = 0;
  string service, flag;
};
vector<Flag> flags;

void add_flag(const Flag &flag)
{
  if (opt_verbose) {
    printf("pattern: %s\n", flag.flag.c_str());
    puts("");
  }
  if (! length)
    length = flag.flag.size();
  else if (length != flag.flag.size())
    err_exit(EX_USAGE, "different lengths of patterns: %s", flag.flag.c_str());
  MultiBackwardDAWG::add(flag.flag.size(), flag.flag.c_str());
  flags.push_back(flag);
}

struct Packet
{
  double timestamp = 0;
  u32 offset;
  Packet() {}
  Packet(u32 offset) : offset(offset) {}
  bool operator<(const Packet &rhs) const {
    return offset < rhs.offset;
  }
};

class PCAP
{
public:
  vector<Packet> packets;

  virtual ~PCAP() {}

  virtual bool parse(u32 len, const u8 *a) {
    if (len < 16) return false;
    if (*(u32*)a != 0xa1b2c3d4) return false;
    for (u32 j, i = 24; i <= len-16; i = j) {
      u8 *block = (u8*)a+i;
      j = i+16+*(u32*)&block[8];
      if (j < i+16) return false;
      Packet packet;
      packet.timestamp = *(u32*)&block[0] + double(*(u32*)&block[4]) * 1e-6;
      packet.offset = i;
      packets.push_back(packet);
    }
    return true;
  }

  int offset2pos(u32 offset) {
    return lower_bound(packets.begin(), packets.end(), Packet(offset))-packets.begin();
  }
};

class PCAPNG : public PCAP
{
public:
  u16 tsresol = 6;

  bool parse_interface_description_block(u32 len, const u8 *block) {
    if (len < 4) return false;
    for (u32 j, i = 16; i < len-4; i = j) {
      u16 opt_code = *(u16*)(block+i), opt_len = *(u16*)(block+i+2);
      j = i+2+opt_len;
      j = ((j-1)|3)+1; // aligned to 32-bit
      if (j < i) return false;
      switch (opt_code) {
      case 9: // if_tsresol
        tsresol = block[i+4];
        break;
      case 14: // if_tsoffset
        err_msg("offset %u: option code %d not implemented", i, opt_code);
        return false;
      }
    }
    return true;
  }

  bool parse(u32 len, const u8 *a) override {
    if (len < 8) return false;
    errno = 0;
    for (u32 j, i = 0; i < len-8; i = j) {
      u8 *block = (u8*)a+i;
      u32 block_len = *(u32*)(a+i+4);
      j = i+block_len;
      if (j < i+12 || len < j) return false;
      u32 block_len2 = *(u32*)&a[j-4];
      if (block_len != block_len2) return false;
      switch (*(u32*)block) {
      case 0x0a0d0d0a:
        break;
      case 0x00000001: // Interface Description Block
        if (! parse_interface_description_block(block_len, block))
          return false;
        break;
      case 0x00000003: // Simple Packet Block
        err_msg("offset %u: simple packet block not implemented", i);
        return false;
      case 0x00000006: { // Enhanced Packet Block
        if (block_len < 28) return false;
        Packet packet;
        u64 timestamp = u64(*(u32*)&block[12]) << 32 | *(u32*)&block[16];
        packet.timestamp = timestamp * 1e-6;
        packet.offset = i;
        packets.push_back(packet);
        break;
      }
      default:
        err_msg("offset %u: block type %u not implemented", i, block[i]);
        return false;
      }
    }
    if (tsresol != 6) {
      err_msg("tsresol != 6 not implemented");
      return false;
    }
    return true;
  }
};

bool is_pcapng(const char *file)
{
  const char *p = strrchr(file, '.');
  if (! p) return false;
  for (auto suf: PCAPNG_SUFFIXES)
    if (! strcmp(p, suf))
      return true;
  return false;
}

void run(int dir_fd, const char *path, const char *file)
{
  off_t len;
  PCAP *pcap = NULL;
  struct stat statbuf;
  u8 *haystack = (u8*)MAP_FAILED;
  vector<pair<int,int>> matches;
  int fd = -1;

  errno = 0;
  if (stat(path, &statbuf) < 0)
    err_msg_g("stat");
  if (S_ISDIR(statbuf.st_mode) || S_ISREG(statbuf.st_mode)) {
    fd = ! strcmp(path, "-")
      ? STDIN_FILENO
      : openat(dir_fd < 0 ? AT_FDCWD : dir_fd, file, O_RDONLY);
    if (fd < 0)
      err_msg_g("failed to open `%s'", path);
  }
  if (S_ISDIR(statbuf.st_mode)) {
    if (! opt_recursive)
      err_msg_g("`%s' is a directory", path);
    DIR *dirp = fdopendir(fd);
    if (! dirp)
      err_msg_g("opendir");
    struct dirent dirent, *dirt;
    while (! readdir_r(dirp, &dirent, &dirt) && dirt)
      if (strcmp(dirent.d_name, ".") && strcmp(dirent.d_name, "..")) {
        char *sub_path;
        if (asprintf(&sub_path, "%s/%s", path, dirent.d_name) < 0)
          err_exit(EX_OSERR, "asprintf");
        run(fd, sub_path, dirent.d_name);
        free(sub_path);
      }
    closedir(dirp);
  } else if (S_ISREG(statbuf.st_mode)) {
    if ((len = lseek(fd, 0, SEEK_END)) < 0)
      err_msg_g("lseek `%s'", path);
    if (len > 0) {
      haystack = (u8 *)mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
      if (haystack == (u8 *)MAP_FAILED)
        err_msg_g("mmap `%s'", path);
      if (is_pcapng(path)) {
        pcap = new PCAP;
        if (! pcap->parse(len, haystack)) {
          delete pcap;
          pcap = new PCAPNG;
          if (! pcap->parse(len, haystack))
            err_msg_g("failed to parse `%s'", path);
        }
      }
    }

    MultiBackwardDAWG::search(len, haystack, [&](int id, int offset) {
      matches.emplace_back(id, offset);
    });
    if (opt_count)
      printf("%s\t%zd\n", path, matches.size());
    else {
      for (auto &x: matches) {
        const Flag &flag = flags[x.first];
        int no = -1;
        if (pcap) {
          no = pcap->offset2pos(x.second);
          if (no >= pcap->packets.size()) continue;
          double t = pcap->packets[no].timestamp;
          if (! (flag.timestamp == 0.0 || (flag.timestamp <= t && t < flag.timestamp+FLAG_DURATION))) continue;
        }
        printf("%s", path);
        if (opt_offset) printf("\t%d", x.second);
        printf("\t%s", flag.flag.c_str());
        if (flag.timestamp != 0.0)
          printf("\t%s\t%.6lf", flag.service.c_str(), flag.timestamp);
          printf("\tframe.number==%u", no+1);
        puts("");
      }
    }
  } else if (opt_verbose)
    printf("skip non file/directory `%s'\n", path);

quit:
  if (haystack != (u8 *)MAP_FAILED)
    munmap(haystack, len);
  if (fd >= 0)
    close(fd);
  if (pcap)
    delete pcap;
}

int main(int argc, char *argv[])
{
  const char *pattern_file = NULL;
  int opt;
  static struct option long_options[] = {
    {"byte-offset",         no_argument,       0,   'b'},
    {"count",               no_argument,       0,   'c'},
    {"file",                no_argument,       0,   'f'},
    {"frame-number",        no_argument,       0,   'H'},
    {"help",                no_argument,       0,   'h'},
    {"recursive",           no_argument,       0,   'r'},
    {"verbose",             no_argument,       0,   'v'},
    {0,                     0,                 0,   0},
  };

  while ((opt = getopt_long(argc, argv, "bcf:Hhrv", long_options, NULL)) != -1) {
    switch (opt) {
    case 'b':
      opt_offset = true;
      break;
    case 'c':
      opt_count = true;
      break;
    case 'f':
      pattern_file = optarg;
      break;
    case 'H':
      opt_frame_number = true;
      break;
    case 'h':
      print_usage(stdout);
      break;
    case 'r':
      opt_recursive = true;
      break;
    case 'v':
      opt_verbose = true;
      break;
    case '?':
      print_usage(stderr);
      break;
    }
  }

  char buf[BUF_SIZE];
  MultiBackwardDAWG::init();
  if (pattern_file) {
    FILE *fh = fopen(pattern_file, "r");
    if (! fh)
      err_exit(EX_OSFILE, "fopen");
    while (fgets(buf, sizeof buf, fh)) {
      char *t = buf+strlen(buf)-1;
      if (*t == '\n')
        *t = '\0';
      else if (strlen(buf) == sizeof buf - 1)
        err_exit(EX_USAGE, "pattern `%s` is too long", buf);
      vector<char *> fields;
      char *pattern = buf;
      for (; ; pattern = NULL) {
        char *p = strtok_r(pattern, PATTERN_SEPARATOR, &t);
        if (! p) break;
        fields.push_back(p);
      }
      Flag flag;
      if (fields.size() == 1) {
        flag.flag = fields[0];
        add_flag(flag);
      } else if (fields.size() == 3) {
        flag.timestamp = get_double(fields[0]);
        flag.service = fields[1];
        flag.flag = fields[2];
        add_flag(flag);
      } else
        err_exit(EX_USAGE, "should have 1 or 3 fields");
    }
  } else if (optind < argc) {
    char *pattern = argv[optind++], *t;
    for (; ; pattern = NULL) {
      char *p = strtok_r(pattern, PATTERN_SEPARATOR, &t);
      if (! p) break;
      if (*p) {
        Flag flag;
        flag.flag = p;
        add_flag(flag);
      }
    }
  }
  if (flags.empty())
    err_exit(EX_USAGE, "pattern is not specified");

  if (optind >= argc)
    err_exit(EX_USAGE, "missing file operand");
  REP(i, flags.size())
    MultiBackwardDAWG::mark(i, flags[i].flag.size(), flags[i].flag.c_str());
  FOR(i, optind, argc)
    run(-1, argv[i], argv[i]);
}
