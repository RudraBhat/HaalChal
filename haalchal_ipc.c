#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHANNEL_DIR "channels"
#define STORAGE_DIR "storage"
#define CHATLOG_DIR "chatlogs"
#define CONTACTS_FILE "contacts.db"

#define MAX_NAME_LEN 64
#define MAX_MOBILE_LEN 10
#define MAX_TEXT_LEN 512
#define MAX_TRACKED_PEERS 32

static const int BASE_KEY[3][3] = {
    {6, 24, 1},
    {13, 16, 10},
    {20, 17, 15}};

typedef struct
{
    char sender_name[MAX_NAME_LEN];
    char sender_mobile[MAX_MOBILE_LEN];
    char body[MAX_TEXT_LEN];
} ChatMessage;

typedef struct
{
    char username[MAX_NAME_LEN];
    char mobile[MAX_MOBILE_LEN];
    char fifo_path[256];
    int fifo_fd;
    pthread_mutex_t *log_lock;
} ListenerContext;

static volatile sig_atomic_t running = 1;
static pthread_mutex_t contacts_lock = PTHREAD_MUTEX_INITIALIZER;

static int mod26(int value)
{
    int result = value % 26;
    if (result < 0)
        result += 26;
    return result;
}

static int mod_inverse(int value)
{
    value = mod26(value);
    for (int i = 1; i < 26; ++i)
    {
        if (mod26(value * i) == 1)
        {
            return i;
        }
    }
    return -1;
}

static int determinant_mod26(const int M[3][3])
{
    int det =
        M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1]) -
        M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0]) +
        M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0]);
    return mod26(det);
}

static int invert_key_matrix(int K[3][3], int Kinv[3][3])
{
    int det = determinant_mod26(K);
    int det_inv = mod_inverse(det);
    if (det_inv == -1)
        return 0;

    int a = K[0][0], b = K[0][1], c = K[0][2];
    int d = K[1][0], e = K[1][1], f = K[1][2];
    int g = K[2][0], h = K[2][1], i = K[2][2];

    int cof[3][3];
    cof[0][0] = (e * i - f * h);
    cof[0][1] = -(d * i - f * g);
    cof[0][2] = (d * h - e * g);

    cof[1][0] = -(b * i - c * h);
    cof[1][1] = (a * i - c * g);
    cof[1][2] = -(a * h - b * g);

    cof[2][0] = (b * f - c * e);
    cof[2][1] = -(a * f - c * d);
    cof[2][2] = (a * e - b * d);

    for (int i = 0; i < 3; ++i)
    {
        for (int j = 0; j < 3; ++j)
        {
            Kinv[i][j] = mod26(det_inv * cof[j][i]);
        }
    }

    return 1;
}

static int sum_of_digits(const char *mobile)
{
    int sum = 0;
    for (size_t i = 0; mobile[i]; ++i)
    {
        if (isdigit((unsigned char)mobile[i]))
        {
            sum += mobile[i] - '0';
        }
    }
    return sum;
}

static void ordered_mobiles(const char *a, const char *b, const char **first, const char **second)
{
    if (strcmp(a, b) <= 0)
    {
        *first = a;
        *second = b;
    }
    else
    {
        *first = b;
        *second = a;
    }
}

static void copy_matrix(const int src[3][3], int dest[3][3])
{
    for (int i = 0; i < 3; ++i)
    {
        for (int j = 0; j < 3; ++j)
        {
            dest[i][j] = src[i][j];
        }
    }
}

static void generate_key_matrix(const char *mobileA, const char *mobileB, int K[3][3])
{
    const char *first;
    const char *second;
    ordered_mobiles(mobileA, mobileB, &first, &second);

    int sumA = sum_of_digits(first);
    int sumB = sum_of_digits(second);
    int T = (sumA + sumB) % 26;

    for (int attempt = 0; attempt < 5; ++attempt)
    {
        int candidate[3][3];
        copy_matrix(BASE_KEY, candidate);
        int adjust = (T + attempt) % 26;
        for (int i = 0; i < 3; ++i)
        {
            candidate[i][i] = mod26(candidate[i][i] + adjust);
        }
        int dummy[3][3];
        if (invert_key_matrix(candidate, dummy))
        {
            copy_matrix(candidate, K);
            return;
        }
    }

    copy_matrix(BASE_KEY, K);
}

static void normalize_plaintext(const char *input, char *output, size_t out_size)
{
    size_t idx = 0;
    for (size_t i = 0; input[i] && idx + 1 < out_size; ++i)
    {
        unsigned char c = (unsigned char)input[i];
        if (isalpha(c))
        {
            output[idx++] = (char)toupper(c);
        }
        else if (c == ' ')
        {
            output[idx++] = 'X';
        }
    }
    if (idx == 0 && out_size > 1)
    {
        output[idx++] = 'X';
    }
    output[idx] = '\0';
}

static void encrypt_message(const int K[3][3], const char *plaintext, char *ciphertext)
{
    char buffer[MAX_TEXT_LEN];
    normalize_plaintext(plaintext, buffer, sizeof(buffer));

    size_t len = strlen(buffer);
    size_t padded_len = (len % 3 == 0) ? len : len + (3 - (len % 3));
    while (len < padded_len && len + 1 < sizeof(buffer))
    {
        buffer[len++] = 'X';
        buffer[len] = '\0';
    }

    size_t out_idx = 0;
    for (size_t i = 0; i < len; i += 3)
    {
        int vec[3];
        for (int j = 0; j < 3; ++j)
        {
            vec[j] = buffer[i + j] - 'A';
        }

        for (int row = 0; row < 3; ++row)
        {
            int sum = 0;
            for (int col = 0; col < 3; ++col)
            {
                sum += K[row][col] * vec[col];
            }
            ciphertext[out_idx++] = (char)('A' + mod26(sum));
        }
    }
    ciphertext[out_idx] = '\0';
}

static char restore_char_from_cipher(int value)
{
    char c = (char)('A' + mod26(value));
    if (c == 'X')
        return ' ';
    return (char)tolower(c);
}

static void decrypt_message(const int Kinv[3][3], const char *ciphertext, char *plaintext)
{
    size_t len = strlen(ciphertext);
    char filtered[MAX_TEXT_LEN];
    size_t f_idx = 0;
    for (size_t i = 0; i < len && f_idx + 1 < sizeof(filtered); ++i)
    {
        if (isalpha((unsigned char)ciphertext[i]))
        {
            filtered[f_idx++] = (char)toupper((unsigned char)ciphertext[i]);
        }
    }
    filtered[f_idx] = '\0';

    if (f_idx == 0)
    {
        plaintext[0] = '\0';
        return;
    }

    if (f_idx % 3 != 0)
    {
        size_t padded_len = f_idx + (3 - (f_idx % 3));
        while (f_idx < padded_len && f_idx + 1 < sizeof(filtered))
        {
            filtered[f_idx++] = 'X';
        }
        filtered[f_idx] = '\0';
    }

    size_t out_idx = 0;
    for (size_t i = 0; i < f_idx; i += 3)
    {
        int vec[3];
        for (int j = 0; j < 3; ++j)
        {
            vec[j] = filtered[i + j] - 'A';
        }

        for (int row = 0; row < 3; ++row)
        {
            int sum = 0;
            for (int col = 0; col < 3; ++col)
            {
                sum += Kinv[row][col] * vec[col];
            }
            plaintext[out_idx++] = restore_char_from_cipher(sum);
        }
    }
    plaintext[out_idx] = '\0';

    while (out_idx > 0 && plaintext[out_idx - 1] == ' ')
    {
        plaintext[--out_idx] = '\0';
    }
}

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static void ensure_dir(const char *path)
{
    if (mkdir(path, 0777) == -1 && errno != EEXIST)
    {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }
}

static void ensure_file_exists(const char *path)
{
    FILE *fp = fopen(path, "a");
    if (fp)
        fclose(fp);
}

static void ensure_user_storage(const char *user)
{
    char path[256];
    ensure_dir(STORAGE_DIR);
    snprintf(path, sizeof(path), "%s/%s", STORAGE_DIR, user);
    ensure_dir(path);
}

static void trim_newline(char *str)
{
    size_t len = strlen(str);
    if (len && str[len - 1] == '\n')
        str[len - 1] = '\0';
}

static void build_fifo_path(const char *mobile, char *out, size_t len)
{
    snprintf(out, len, "%s/%s.fifo", CHANNEL_DIR, mobile);
}

static void chat_log_path(const char *mobile_a, const char *mobile_b, char *out, size_t len)
{
    const char *first = mobile_a;
    const char *second = mobile_b;
    if (strcmp(first, second) > 0)
    {
        first = mobile_b;
        second = mobile_a;
    }
    snprintf(out, len, "%s/%s_%s.txt", CHATLOG_DIR, first, second);
}

static bool last_line_matches(const char *path, const char *line_with_newline)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;
    char buffer[1024];
    char last[1024] = {0};
    while (fgets(buffer, sizeof(buffer), fp))
    {
        strncpy(last, buffer, sizeof(last) - 1);
        last[sizeof(last) - 1] = '\0';
    }
    fclose(fp);
    return (strlen(last) > 0 && strcmp(last, line_with_newline) == 0);
}

static void current_timestamp(char *out, size_t len)
{
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(out, len, "%Y-%m-%d %H:%M:%S", &tm_info);
}

static void append_chat_log(const char *mobile_a, const char *mobile_b, const char *line, pthread_mutex_t *lock)
{
    char path[256];
    chat_log_path(mobile_a, mobile_b, path, sizeof(path));

    pthread_mutex_lock(lock);
    char line_with_newline[1100];
    snprintf(line_with_newline, sizeof(line_with_newline), "%s\n", line);
    if (last_line_matches(path, line_with_newline))
    {
        pthread_mutex_unlock(lock);
        return;
    }

    FILE *fp = fopen(path, "a");
    if (!fp)
    {
        perror("fopen chatlog");
        pthread_mutex_unlock(lock);
        return;
    }
    fputs(line_with_newline, fp);
    fclose(fp);
    pthread_mutex_unlock(lock);
}

static void write_log_entry_with_ciphertext(const char *sender_name,
                                            const char *sender_mobile,
                                            const char *recipient_mobile,
                                            const char *ciphertext,
                                            pthread_mutex_t *lock)
{
    char timestamp[64];
    current_timestamp(timestamp, sizeof(timestamp));
    char entry[1024];
    snprintf(entry, sizeof(entry), "[%s] %s (%s): %s", timestamp, sender_name, sender_mobile, ciphertext);
    append_chat_log(sender_mobile, recipient_mobile, entry, lock);
}

static void log_plaintext_message(const char *sender_name,
                                  const char *sender_mobile,
                                  const char *recipient_mobile,
                                  const char *message,
                                  pthread_mutex_t *lock)
{
    int key[3][3];
    generate_key_matrix(sender_mobile, recipient_mobile, key);
    char cipher[MAX_TEXT_LEN];
    encrypt_message(key, message, cipher);
    write_log_entry_with_ciphertext(sender_name, sender_mobile, recipient_mobile, cipher, lock);
}

static void print_chat_history(const char *mobile_a, const char *mobile_b)
{
    char path[256];
    chat_log_path(mobile_a, mobile_b, path, sizeof(path));
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        printf("No previous messages.\n");
        return;
    }

    int key[3][3];
    generate_key_matrix(mobile_a, mobile_b, key);
    int Kinv[3][3];
    int can_decrypt = invert_key_matrix(key, Kinv);

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        char *sep = strstr(line, ": ");
        if (!sep || !can_decrypt)
        {
            printf("%s", line);
            continue;
        }

        char prefix[512];
        size_t prefix_len = (size_t)(sep - line + 2);
        if (prefix_len >= sizeof(prefix))
            prefix_len = sizeof(prefix) - 1;
        strncpy(prefix, line, prefix_len);
        prefix[prefix_len] = '\0';

        char cipher[MAX_TEXT_LEN];
        strncpy(cipher, sep + 2, sizeof(cipher) - 1);
        cipher[sizeof(cipher) - 1] = '\0';
        trim_newline(cipher);

        char plaintext[MAX_TEXT_LEN];
        decrypt_message(Kinv, cipher, plaintext);
        printf("%s%s\n", prefix, plaintext);
    }
    fclose(fp);
}

static bool load_contact_name(const char *mobile, char *name_out)
{
    pthread_mutex_lock(&contacts_lock);
    FILE *fp = fopen(CONTACTS_FILE, "r");
    if (!fp)
    {
        pthread_mutex_unlock(&contacts_lock);
        return false;
    }

    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), fp))
    {
        char file_mobile[MAX_MOBILE_LEN];
        char file_name[MAX_NAME_LEN];
        if (sscanf(line, "%15[^,],%63[^\n]", file_mobile, file_name) == 2)
        {
            if (strcmp(file_mobile, mobile) == 0)
            {
                strncpy(name_out, file_name, MAX_NAME_LEN - 1);
                name_out[MAX_NAME_LEN - 1] = '\0';
                found = true;
                break;
            }
        }
    }

    fclose(fp);
    pthread_mutex_unlock(&contacts_lock);
    return found;
}

static void append_contact_record(const char *mobile, const char *name)
{
    pthread_mutex_lock(&contacts_lock);
    FILE *fp = fopen(CONTACTS_FILE, "a");
    if (!fp)
    {
        perror("contacts append");
        pthread_mutex_unlock(&contacts_lock);
        return;
    }
    fprintf(fp, "%s,%s\n", mobile, name);
    fclose(fp);
    pthread_mutex_unlock(&contacts_lock);
}

static void register_contact(const char *mobile, char *name_out)
{
    printf("Enter username for mobile %s: ", mobile);
    fflush(stdout);
    if (!fgets(name_out, MAX_NAME_LEN, stdin))
    {
        fprintf(stderr, "Unable to read username.\n");
        exit(EXIT_FAILURE);
    }
    trim_newline(name_out);
    append_contact_record(mobile, name_out);
}

static void ensure_contact(const char *mobile, char *name_out)
{
    if (load_contact_name(mobile, name_out))
        return;
    register_contact(mobile, name_out);
}

static void add_contact_if_missing(const char *mobile, const char *name)
{
    char existing[MAX_NAME_LEN];
    if (load_contact_name(mobile, existing))
        return;
    append_contact_record(mobile, name);
}

static int open_listener_fifo(const char *path)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd == -1)
    {
        perror("open fifo (read)");
    }
    return fd;
}

static void *listener_thread(void *arg)
{
    ListenerContext *ctx = (ListenerContext *)arg;
    ChatMessage msg;

    while (running)
    {
        ssize_t bytes = read(ctx->fifo_fd, &msg, sizeof(msg));
        if (bytes == (ssize_t)sizeof(msg))
        {
            if (strcmp(msg.sender_mobile, "__SHUTDOWN__") == 0)
                break;

            add_contact_if_missing(msg.sender_mobile, msg.sender_name);
            int key[3][3];
            generate_key_matrix(ctx->mobile, msg.sender_mobile, key);
            int Kinv[3][3];
            char plaintext[MAX_TEXT_LEN];
            if (invert_key_matrix(key, Kinv))
            {
                decrypt_message(Kinv, msg.body, plaintext);
            }
            else
            {
                strncpy(plaintext, msg.body, sizeof(plaintext) - 1);
                plaintext[sizeof(plaintext) - 1] = '\0';
            }
            printf("\n[%s] %s\n> ", msg.sender_name, plaintext);
            fflush(stdout);
        }
        else if (bytes == 0)
        {
            if (!running)
                break;
            close(ctx->fifo_fd);
            ctx->fifo_fd = open_listener_fifo(ctx->fifo_path);
            if (ctx->fifo_fd == -1)
                break;
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                usleep(100000);
                continue;
            }
            if (errno == EINTR)
                continue;
        }
    }

    return NULL;
}

static void maybe_show_history(const char *self_mobile,
                               const char *peer_mobile,
                               const char *peer_name,
                               char shown[][MAX_MOBILE_LEN],
                               size_t *count)
{
    for (size_t i = 0; i < *count; ++i)
    {
        if (strcmp(shown[i], peer_mobile) == 0)
            return;
    }

    printf("\n--- Previous conversation with %s (%s) ---\n", peer_name, peer_mobile);
    print_chat_history(self_mobile, peer_mobile);
    printf("------------------------------------------\n");

    if (*count < MAX_TRACKED_PEERS)
    {
        strncpy(shown[*count], peer_mobile, MAX_MOBILE_LEN - 1);
        shown[*count][MAX_MOBILE_LEN - 1] = '\0';
        (*count)++;
    }
}

static void list_user_files(const char *user)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", STORAGE_DIR, user);
    DIR *dir = opendir(path);
    if (!dir)
    {
        perror("opendir storage");
        return;
    }
    struct dirent *entry;
    printf("Files for %s:\n", user);
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_REG)
        {
            printf("- %s\n", entry->d_name);
        }
    }
    closedir(dir);
}

static int send_chat_message(const char *sender_name,
                             const char *sender_mobile,
                             const char *recipient_mobile,
                             const char *recipient_name,
                             const char *text,
                             pthread_mutex_t *log_lock)
{
    char fifo_path[256];
    build_fifo_path(recipient_mobile, fifo_path, sizeof(fifo_path));

    int fd = -1;
    const int max_attempts = 20;
    for (int attempt = 0; attempt < max_attempts; ++attempt)
    {
        fd = open(fifo_path, O_WRONLY | O_NONBLOCK);
        if (fd != -1)
            break;
        if (errno != ENXIO && errno != ENOENT)
            break;
        usleep(100000); // wait 100ms for listener to attach
    }
    if (fd == -1)
    {
        fprintf(stderr, "Unable to reach %s (%s). Is their process running?\n", recipient_name, recipient_mobile);
        return -1;
    }

    int key[3][3];
    generate_key_matrix(sender_mobile, recipient_mobile, key);
    char ciphertext[MAX_TEXT_LEN];
    encrypt_message(key, text, ciphertext);

    ChatMessage msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.sender_name, sender_name, sizeof(msg.sender_name) - 1);
    strncpy(msg.sender_mobile, sender_mobile, sizeof(msg.sender_mobile) - 1);
    strncpy(msg.body, ciphertext, sizeof(msg.body) - 1);

    if (write(fd, &msg, sizeof(msg)) != (ssize_t)sizeof(msg))
    {
        perror("write message");
        close(fd);
        return -1;
    }

    close(fd);

    write_log_entry_with_ciphertext(sender_name, sender_mobile, recipient_mobile, ciphertext, log_lock);

    return 0;
}

static void child_copy_file(const char *sender_name,
                            const char *recipient_name,
                            const char *filepath,
                            int status_fd)
{
    FILE *src = fopen(filepath, "rb");
    if (!src)
    {
        dprintf(status_fd, "Failed to open %s\n", filepath);
        _exit(EXIT_FAILURE);
    }

    const char *filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;

    char dest_path[256];
    snprintf(dest_path, sizeof(dest_path), "%s/%s/%s", STORAGE_DIR, recipient_name, filename);
    FILE *dst = fopen(dest_path, "wb");
    if (!dst)
    {
        dprintf(status_fd, "Cannot write to %s\n", dest_path);
        fclose(src);
        _exit(EXIT_FAILURE);
    }

    char buffer[1024];
    size_t read_bytes;
    while ((read_bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
    {
        fwrite(buffer, 1, read_bytes, dst);
    }

    fclose(src);
    fclose(dst);

    char note[256];
    snprintf(note, sizeof(note), "%s shared %s with %s", sender_name, filename, recipient_name);
    dprintf(status_fd, "%s\n", note);

    _exit(EXIT_SUCCESS);
}

static void send_file_to_user(const char *sender_name,
                              const char *sender_mobile,
                              const char *recipient_name,
                              const char *recipient_mobile,
                              const char *filepath,
                              pthread_mutex_t *log_lock)
{
    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        perror("pipe");
        return;
    }

    ensure_user_storage(recipient_name);

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0)
    {
        close(pipefd[0]);
        child_copy_file(sender_name, recipient_name, filepath, pipefd[1]);
    }

    close(pipefd[1]);
    char status_msg[256] = {0};
    read(pipefd[0], status_msg, sizeof(status_msg) - 1);
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    if (strlen(status_msg) == 0)
        strcpy(status_msg, "File transfer finished.\n");

    printf("%s", status_msg);

    char log_message[512];
    snprintf(log_message, sizeof(log_message), "shared file %s with %s", filepath, recipient_name);
    log_plaintext_message(sender_name, sender_mobile, recipient_mobile, log_message, log_lock);

    const char *filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;

    char notify[300];
    snprintf(notify, sizeof(notify), "%s sent you file %s", sender_name, filename);
    send_chat_message(sender_name, sender_mobile, recipient_mobile, recipient_name, notify, log_lock);
}

static void usage(void)
{
    fprintf(stderr, "Run the program and follow prompts for your mobile number.\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    ensure_dir(CHANNEL_DIR);
    ensure_dir(CHATLOG_DIR);
    ensure_file_exists(CONTACTS_FILE);

    char self_mobile[MAX_MOBILE_LEN];
    char self_name[MAX_NAME_LEN];

    printf("Enter your mobile number: ");
    fflush(stdout);
    if (!fgets(self_mobile, sizeof(self_mobile), stdin))
        usage();
    trim_newline(self_mobile);
    if (strlen(self_mobile) == 0)
        usage();

    ensure_contact(self_mobile, self_name);
    ensure_user_storage(self_name);

    printf("Welcome, %s (%s)!\n", self_name, self_mobile);

    char fifo_path[256];
    build_fifo_path(self_mobile, fifo_path, sizeof(fifo_path));
    if (mkfifo(fifo_path, 0666) == -1 && errno != EEXIST)
    {
        perror("mkfifo");
        return EXIT_FAILURE;
    }

    ListenerContext ctx = {0};
    strncpy(ctx.username, self_name, sizeof(ctx.username) - 1);
    strncpy(ctx.mobile, self_mobile, sizeof(ctx.mobile) - 1);
    strncpy(ctx.fifo_path, fifo_path, sizeof(ctx.fifo_path) - 1);

    pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
    ctx.log_lock = &log_lock;
    ctx.fifo_fd = open_listener_fifo(ctx.fifo_path);
    if (ctx.fifo_fd == -1)
        return EXIT_FAILURE;

    pthread_t listener_tid;
    if (pthread_create(&listener_tid, NULL, listener_thread, &ctx) != 0)
    {
        perror("pthread_create");
        close(ctx.fifo_fd);
        return EXIT_FAILURE;
    }

    printf("Commands:\n");
    printf("  msg <mobile> <text>\n");
    printf("  sendfile <mobile> <path>\n");
    printf("  history <mobile>\n");
    printf("  list\n");
    printf("  exit\n");

    char history_shown[MAX_TRACKED_PEERS][MAX_MOBILE_LEN] = {{0}};
    size_t shown_count = 0;

    char line[1024];
    while (running && fgets(line, sizeof(line), stdin))
    {
        trim_newline(line);
        if (strlen(line) == 0)
        {
            printf("> ");
            fflush(stdout);
            continue;
        }

        char *command = strtok(line, " ");
        if (!command)
            continue;

        if (strcmp(command, "msg") == 0)
        {
            char *recipient_mobile = strtok(NULL, " ");
            char *text = strtok(NULL, "");
            if (!recipient_mobile || !text)
            {
                printf("Usage: msg <mobile> <text>\n");
            }
            else
            {
                char recipient_name[MAX_NAME_LEN];
                ensure_contact(recipient_mobile, recipient_name);
                maybe_show_history(self_mobile, recipient_mobile, recipient_name, history_shown, &shown_count);
                send_chat_message(self_name, self_mobile, recipient_mobile, recipient_name, text, &log_lock);
            }
        }
        else if (strcmp(command, "sendfile") == 0)
        {
            char *recipient_mobile = strtok(NULL, " ");
            char *path = strtok(NULL, "");
            if (!recipient_mobile || !path)
            {
                printf("Usage: sendfile <mobile> <path>\n");
            }
            else
            {
                char recipient_name[MAX_NAME_LEN];
                ensure_contact(recipient_mobile, recipient_name);
                send_file_to_user(self_name, self_mobile, recipient_name, recipient_mobile, path, &log_lock);
            }
        }
        else if (strcmp(command, "history") == 0)
        {
            char *peer_mobile = strtok(NULL, " ");
            if (!peer_mobile)
            {
                printf("Usage: history <mobile>\n");
            }
            else
            {
                char peer_name[MAX_NAME_LEN];
                if (!load_contact_name(peer_mobile, peer_name))
                {
                    printf("Unknown mobile %s. Add it with msg/sendfile first.\n", peer_mobile);
                }
                else
                {
                    print_chat_history(self_mobile, peer_mobile);
                }
            }
        }
        else if (strcmp(command, "list") == 0)
        {
            list_user_files(self_name);
        }
        else if (strcmp(command, "exit") == 0)
        {
            running = 0;
            break;
        }
        else
        {
            printf("Unknown command.\n");
        }

        printf("> ");
        fflush(stdout);
    }

    running = 0;
    ChatMessage shutdown_msg = {0};
    strcpy(shutdown_msg.sender_mobile, "__SHUTDOWN__");
    int tmp_fd = open(fifo_path, O_WRONLY | O_NONBLOCK);
    if (tmp_fd != -1)
    {
        write(tmp_fd, &shutdown_msg, sizeof(shutdown_msg));
        close(tmp_fd);
    }

    pthread_join(listener_tid, NULL);
    close(ctx.fifo_fd);
    unlink(fifo_path);

    printf("\nGoodbye!\n");
    return 0;
}
