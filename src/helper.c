#ifndef _WIN32
#include <pwd.h>
#endif /* _WIN32 */

#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "debug.h"

/** Free memory space */
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

#ifdef _WIN32
char *ncot_get_user_home_dir(void) {
  char tmp[MAX_PATH] = {0};
  char *szPath = NULL;

  if (SHGetSpecialFolderPathA(NULL, tmp, CSIDL_PROFILE, TRUE)) {
    szPath = malloc(strlen(tmp) + 1);
    if (szPath == NULL) {
      return NULL;
    }

    strcpy(szPath, tmp);
    return szPath;
  }

  return NULL;
}

#else /* _WIN32 */

#ifndef NSS_BUFLEN_PASSWD
#define NSS_BUFLEN_PASSWD 4096
#endif /* NSS_BUFLEN_PASSWD */

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 1

char*
ncot_get_user_home_dir(void)
{
    char *szPath = NULL;
    struct passwd pwd;
    struct passwd *pwdbuf = NULL;
    char buf[NSS_BUFLEN_PASSWD] = {0};
    int rc;

    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    if (rc != 0 || pwdbuf == NULL ) {
        szPath = getenv("HOME");
        if (szPath == NULL) {
            return NULL;
        }
        snprintf(buf, sizeof(buf), "%s", szPath);

        return strdup(buf);
    }

    szPath = strdup(pwd.pw_dir);

    NCOT_DEBUG("%s", szPath);
    return szPath;
}
#endif

/**
 * Shamelessly stolen from libssh
 *
 * @brief Expand a directory starting with a tilde '~'
 *
 * @param[in]  d        The directory to expand.
 *
 * @return              The expanded directory, NULL on error.
 */
char*
ncot_path_expand_tilde(const char *d) {
    char *h = NULL, *r;
    const char *p;
    size_t ld;
    size_t lh = 0;

    if (d[0] != '~') {
        return strdup(d);
    }
    d++;

    /* handle ~user/path */
    p = strchr(d, '/');
    if (p != NULL && p > d) {
#ifdef _WIN32
        return strdup(d);
#else
        struct passwd *pw;
        size_t s = p - d;
        char u[128];

        if (s >= sizeof(u)) {
            return NULL;
        }
        memcpy(u, d, s);
        u[s] = '\0';
        pw = getpwnam(u);
        if (pw == NULL) {
            return NULL;
        }
        ld = strlen(p);
        h = strdup(pw->pw_dir);
#endif
    } else {
        ld = strlen(d);
        p = (char *) d;
        h = ncot_get_user_home_dir();
    }
    if (h == NULL) {
        return NULL;
    }
    lh = strlen(h);

    r = malloc(ld + lh + 1);
    if (r == NULL) {
        SAFE_FREE(h);
        return NULL;
    }

    if (lh > 0) {
        memcpy(r, h, lh);
    }
    SAFE_FREE(h);
    memcpy(r + lh, p, ld + 1);

    return r;
}

