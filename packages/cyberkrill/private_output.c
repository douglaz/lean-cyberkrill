/*
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
*/
#include <lean/lean.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* No pathname check/chmod interval and no buffered writes or ignored close error. */
LEAN_EXPORT lean_obj_res lck_write_private_file(b_lean_obj_arg path,
                                               b_lean_obj_arg content) {
    const char *name = lean_string_cstr(path);
    if (memchr(name, '\0', lean_string_size(path) - 1) != NULL)
        return lean_io_result_mk_error(lean_decode_io_error(EINVAL, path));
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        int error = errno;
        struct stat status;
        /* Linux also returns EISDIR for missing slash-terminated paths.
           Metadata only classifies an already-failed open; it permits no write. */
        if (error == EISDIR && lstat(name, &status) == 0) error = EEXIST;
        return lean_io_result_mk_error(lean_decode_io_error(error, path));
    }
    const char *bytes = lean_string_cstr(content);
    size_t remaining = lean_string_size(content) - 1;
    int error = 0;
    while (remaining != 0) {
        ssize_t count = write(fd, bytes, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            error = count < 0 ? errno : EIO;
            break;
        }
        bytes += count;
        remaining -= (size_t)count;
    }
    /* On Linux a failed close releases the descriptor; retrying can close another. */
    if (close(fd) != 0 && error == 0) error = errno;
    if (error != 0)
        return lean_io_result_mk_error(lean_decode_io_error(error, path));
    return lean_io_result_mk_ok(lean_box(0));
}
