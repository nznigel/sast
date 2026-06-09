/**
 * ============================================================
 *  CWE TEST HARNESS FOR SAST EVALUATION
 *  Purpose : Evaluate SonarQube (or any SAST tool) coverage
 *            against the CWE Top 50+ weaknesses.
 *  Author  : Generated for digitalsafety.org
 *  Compiler: g++ -std=c++17 -w -o cwe_test_harness cwe_test_harness.cpp
 *
 *  *** DO NOT DEPLOY OR EXECUTE IN PRODUCTION ***
 *  *** THIS FILE EXISTS SOLELY AS A SAST TEST TARGET ***
 *
 *  Each section is tagged:
 *    CWE-NNN  Short name
 *    TRIGGER  The exact pattern the SAST tool should detect
 * ============================================================
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <functional>
#include <memory>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cmath>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>

// ── Forward declarations ──────────────────────────────────────────────────────
void section_memory_safety();
void section_injection();
void section_numeric();
void section_concurrency();
void section_resource_mgmt();
void section_crypto_errors();
void section_path_and_io();
void section_type_errors();
void section_control_flow();
void section_miscellaneous();

// =============================================================================
// SECTION 1 — MEMORY SAFETY
// =============================================================================

// ── CWE-120 Buffer Copy without Checking Size of Input ────────────────────────
// TRIGGER: strcpy() with no bounds check
void cwe120_buffer_copy_no_size_check(const char *input)
{
    char dest[64]; // fixed buffer
    strcpy(dest, input); // CWE-120: no length validation before copy
    printf("dest: %s\n", dest);
}

// ── CWE-121 Stack-Based Buffer Overflow ───────────────────────────────────────
// TRIGGER: writing past end of a stack-allocated array
void cwe121_stack_overflow()
{
    char buf[16];
    memset(buf, 'A', 32); // CWE-121: overflow — writes 32 bytes into 16-byte buffer
}

// ── CWE-122 Heap-Based Buffer Overflow ────────────────────────────────────────
// TRIGGER: writing beyond malloc'd bounds
void cwe122_heap_overflow()
{
    char *buf = (char *)malloc(16);
    if (!buf) return;
    memset(buf, 'B', 64); // CWE-122: heap overflow — 64 bytes into 16-byte heap block
    free(buf);
}

// ── CWE-124 Buffer Underwrite ─────────────────────────────────────────────────
// TRIGGER: writing before the start of a buffer
void cwe124_buffer_underwrite()
{
    char buf[32];
    char *p = buf;
    *(p - 4) = 'X'; // CWE-124: write before buffer start
}

// ── CWE-125 Out-of-bounds Read ────────────────────────────────────────────────
// TRIGGER: reading beyond array end
void cwe125_oob_read()
{
    int arr[5] = {1, 2, 3, 4, 5};
    int val = arr[10]; // CWE-125: out-of-bounds read at index 10
    printf("val: %d\n", val);
}

// ── CWE-126 Buffer Over-read ──────────────────────────────────────────────────
// TRIGGER: strlen on a non-null-terminated buffer
void cwe126_buffer_over_read()
{
    char buf[8];
    memset(buf, 'A', 8); // deliberately no null terminator
    size_t len = strlen(buf); // CWE-126: reads past end of buffer
    printf("len: %zu\n", len);
}

// ── CWE-127 Buffer Under-read ─────────────────────────────────────────────────
// TRIGGER: pointer arithmetic before base address
void cwe127_buffer_under_read()
{
    int arr[8] = {};
    int *p = arr;
    int val = *(p - 1); // CWE-127: read before buffer start
    printf("val: %d\n", val);
}

// ── CWE-415 Double Free ───────────────────────────────────────────────────────
// TRIGGER: free() called twice on same pointer
void cwe415_double_free()
{
    char *p = (char *)malloc(32);
    free(p);
    free(p); // CWE-415: double free — undefined behaviour
}

// ── CWE-416 Use After Free ────────────────────────────────────────────────────
// TRIGGER: accessing memory after free()
void cwe416_use_after_free()
{
    char *p = (char *)malloc(32);
    strcpy(p, "hello");
    free(p);
    printf("%s\n", p); // CWE-416: use-after-free read
}

// ── CWE-476 NULL Pointer Dereference ─────────────────────────────────────────
// TRIGGER: deref of pointer without null check
int *cwe476_return_null() { return nullptr; }

void cwe476_null_deref()
{
    int *p = cwe476_return_null();
    *p = 42; // CWE-476: dereference of NULL pointer
}

// ── CWE-590 Free of Memory Not on Heap ───────────────────────────────────────
// TRIGGER: free() on stack address
void cwe590_free_stack_memory()
{
    int x = 5;
    int *p = &x;
    free(p); // CWE-590: freeing stack-allocated variable
}

// ── CWE-761 Free of Pointer Not at Start of Buffer ───────────────────────────
// TRIGGER: free() on interior pointer
void cwe761_free_mid_pointer()
{
    char *buf = (char *)malloc(64);
    if (!buf) return;
    buf += 8;   // advance pointer into buffer
    free(buf);  // CWE-761: freeing pointer not at allocation start
}

// ── CWE-401 Memory Leak ───────────────────────────────────────────────────────
// TRIGGER: allocated memory never freed
void cwe401_memory_leak()
{
    char *p = (char *)malloc(256); // CWE-401: allocated but never freed
    if (!p) return;
    strcpy(p, "leaked data");
    // p deliberately not freed
}

// ── CWE-562 Return of Stack Variable Address ──────────────────────────────────
// TRIGGER: returning pointer to local variable
char *cwe562_return_stack_address()
{
    char local_buf[64];
    snprintf(local_buf, sizeof(local_buf), "local data");
    return local_buf; // CWE-562: dangling pointer — local goes out of scope
}

void section_memory_safety()
{
    printf("\n=== SECTION 1: MEMORY SAFETY ===\n");
    cwe120_buffer_copy_no_size_check("safe_length");
    cwe121_stack_overflow();
    cwe122_heap_overflow();
    cwe124_buffer_underwrite();
    cwe125_oob_read();
    cwe126_buffer_over_read();
    cwe127_buffer_under_read();
    cwe401_memory_leak();
    char *stale = cwe562_return_stack_address();
    (void)stale;
}

// =============================================================================
// SECTION 2 — INJECTION
// =============================================================================

// ── CWE-78 OS Command Injection ───────────────────────────────────────────────
// TRIGGER: user input passed directly to system()
void cwe78_command_injection(const char *user_input)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", user_input); // CWE-78: unsanitised input in shell command
    system(cmd);
}

// ── CWE-89 SQL Injection ──────────────────────────────────────────────────────
// TRIGGER: string concatenation building a query
std::string cwe89_sql_injection(const std::string &username)
{
    // CWE-89: unsanitised input concatenated into SQL
    return "SELECT * FROM users WHERE name = '" + username + "'";
}

// ── CWE-134 Uncontrolled Format String ───────────────────────────────────────
// TRIGGER: user-controlled format string passed to printf
void cwe134_format_string(const char *user_fmt)
{
    printf(user_fmt); // CWE-134: format string from external source
}

// ── CWE-90 LDAP Injection ─────────────────────────────────────────────────────
// TRIGGER: user data embedded directly in LDAP filter string
std::string cwe90_ldap_injection(const std::string &user)
{
    // CWE-90: unsanitised user data in LDAP query
    return "(&(uid=" + user + ")(objectClass=person))";
}

// ── CWE-77 Command Injection (general) ───────────────────────────────────────
// TRIGGER: popen() with unsanitised input
void cwe77_command_injection_popen(const std::string &filename)
{
    std::string cmd = "ls -la " + filename; // CWE-77: tainted data in shell command
    FILE *fp = popen(cmd.c_str(), "r");
    if (fp) pclose(fp);
}

void section_injection()
{
    printf("\n=== SECTION 2: INJECTION ===\n");
    cwe78_command_injection("127.0.0.1");
    printf("SQL: %s\n", cwe89_sql_injection("admin").c_str());
    cwe134_format_string("Hello World\n");
    cwe77_command_injection_popen("/tmp/test.txt");
}

// =============================================================================
// SECTION 3 — NUMERIC ERRORS
// =============================================================================

// ── CWE-190 Integer Overflow or Wraparound ────────────────────────────────────
// TRIGGER: arithmetic that can overflow signed int
void cwe190_integer_overflow()
{
    int x = INT_MAX;
    int y = x + 1; // CWE-190: signed integer overflow — undefined behaviour
    printf("overflow: %d\n", y);
}

// ── CWE-191 Integer Underflow ─────────────────────────────────────────────────
// TRIGGER: subtraction below INT_MIN
void cwe191_integer_underflow()
{
    int x = INT_MIN;
    int y = x - 1; // CWE-191: signed integer underflow
    printf("underflow: %d\n", y);
}

// ── CWE-369 Divide by Zero ────────────────────────────────────────────────────
// TRIGGER: division without zero guard
void cwe369_divide_by_zero(int denominator)
{
    int result = 100 / denominator; // CWE-369: potential divide-by-zero
    printf("result: %d\n", result);
}

// ── CWE-197 Numeric Truncation Error ──────────────────────────────────────────
// TRIGGER: narrowing conversion loses data
void cwe197_numeric_truncation()
{
    long long big = 0x1122334455667788LL;
    int small = (int)big; // CWE-197: truncation — high bits discarded
    printf("truncated: %d\n", small);
}

// ── CWE-194 Unexpected Sign Extension ─────────────────────────────────────────
// TRIGGER: signed char widened to int preserves sign
void cwe194_sign_extension()
{
    signed char c = -1;
    unsigned int u = c; // CWE-194: sign extension — u becomes 0xFFFFFFFF
    printf("sign extended: %u\n", u);
}

// ── CWE-195 Signed to Unsigned Conversion Error ───────────────────────────────
// TRIGGER: negative signed used as size
void cwe195_signed_to_unsigned(int n)
{
    // CWE-195: if n < 0, cast to size_t is a huge number
    char *buf = (char *)malloc((size_t)n);
    if (buf) free(buf);
}

// ── CWE-681 Incorrect Conversion Between Numeric Types ───────────────────────
// TRIGGER: double → int truncation without range check
void cwe681_incorrect_type_conversion()
{
    double d = 1e18;
    int i = (int)d; // CWE-681: value far exceeds INT_MAX, result is undefined
    printf("converted: %d\n", i);
}

void section_numeric()
{
    printf("\n=== SECTION 3: NUMERIC ERRORS ===\n");
    cwe190_integer_overflow();
    cwe191_integer_underflow();
    cwe369_divide_by_zero(0);
    cwe197_numeric_truncation();
    cwe194_sign_extension();
    cwe195_signed_to_unsigned(-1);
    cwe681_incorrect_type_conversion();
}

// =============================================================================
// SECTION 4 — CONCURRENCY
// =============================================================================

static int g_shared_counter = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

// ── CWE-362 Race Condition (TOCTOU) ───────────────────────────────────────────
// TRIGGER: check-then-act on shared resource without lock
void cwe362_race_condition_toctou(const char *path)
{
    // CWE-362: access() then open() — file state can change between the two
    if (access(path, W_OK) == 0) {
        // window opens here — attacker can swap the file (symlink attack)
        int fd = open(path, O_WRONLY);
        if (fd >= 0) close(fd);
    }
}

// ── CWE-366 Race Condition within a Thread ────────────────────────────────────
// TRIGGER: shared variable incremented without synchronisation
void *cwe366_unsynchronised_thread(void *arg)
{
    for (int i = 0; i < 10000; i++) {
        g_shared_counter++; // CWE-366: unsynchronised write to shared state
    }
    return nullptr;
}

void cwe366_race_demo()
{
    pthread_t t1, t2;
    pthread_create(&t1, nullptr, cwe366_unsynchronised_thread, nullptr);
    pthread_create(&t2, nullptr, cwe366_unsynchronised_thread, nullptr);
    pthread_join(t1, nullptr);
    pthread_join(t2, nullptr);
}

// ── CWE-400 Uncontrolled Resource Consumption ─────────────────────────────────
// TRIGGER: loop without upper bound on external-driven count
void cwe400_resource_exhaustion(int user_count)
{
    // CWE-400: attacker controls allocation count
    std::vector<std::vector<char>> chunks;
    for (int i = 0; i < user_count; i++) {
        chunks.push_back(std::vector<char>(1024 * 1024)); // 1 MB per iteration
    }
}

// ── CWE-833 Deadlock ──────────────────────────────────────────────────────────
// TRIGGER: two mutexes acquired in inconsistent order
static std::mutex g_mtx_a;
static std::mutex g_mtx_b;

void cwe833_deadlock_thread1()
{
    std::lock_guard<std::mutex> la(g_mtx_a); // CWE-833: acquires A then B
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::lock_guard<std::mutex> lb(g_mtx_b);
}

void cwe833_deadlock_thread2()
{
    std::lock_guard<std::mutex> lb(g_mtx_b); // CWE-833: acquires B then A — deadlock risk
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    std::lock_guard<std::mutex> la(g_mtx_a);
}

void section_concurrency()
{
    printf("\n=== SECTION 4: CONCURRENCY ===\n");
    cwe362_race_condition_toctou("/tmp/test_cwe362.txt");
    cwe366_race_demo();
}

// =============================================================================
// SECTION 5 — RESOURCE MANAGEMENT
// =============================================================================

// ── CWE-404 Improper Resource Shutdown ────────────────────────────────────────
// TRIGGER: file descriptor not closed on error path
void cwe404_resource_not_closed(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char buf[256];
    if (!fgets(buf, sizeof(buf), f)) {
        return; // CWE-404: f never fclose()'d on this error path
    }
    fclose(f);
}

// ── CWE-772 Missing Release of Resource after Effective Lifetime ──────────────
// TRIGGER: conditional return bypasses cleanup
int cwe772_missing_release(bool fail_early)
{
    int *data = new int[1000];
    if (fail_early) {
        return -1; // CWE-772: heap allocation leaked on this branch
    }
    delete[] data;
    return 0;
}

// ── CWE-675 Duplicate Operations on Resource ─────────────────────────────────
// TRIGGER: fclose() called twice
void cwe675_double_close(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    fclose(f);
    fclose(f); // CWE-675: double close — undefined behaviour
}

// ── CWE-459 Incomplete Cleanup ────────────────────────────────────────────────
// TRIGGER: partial cleanup on exception path
void cwe459_incomplete_cleanup()
{
    char *buf1 = (char *)malloc(64);
    char *buf2 = (char *)malloc(64);
    if (!buf1 || !buf2) {
        free(buf1); // CWE-459: buf2 may leak if buf1 != null but buf2 == null
        return;
    }
    free(buf1);
    free(buf2);
}

void section_resource_mgmt()
{
    printf("\n=== SECTION 5: RESOURCE MANAGEMENT ===\n");
    cwe404_resource_not_closed("/tmp/cwe404_test.txt");
    cwe772_missing_release(true);
    cwe675_double_close("/tmp/cwe675_test.txt");
    cwe459_incomplete_cleanup();
}

// =============================================================================
// SECTION 6 — CRYPTOGRAPHIC ERRORS
// =============================================================================

// ── CWE-321 Hard-coded Cryptographic Key ──────────────────────────────────────
// TRIGGER: key literal in source
void cwe321_hardcoded_key()
{
    const char *key = "s3cr3t_aes_key_hardcoded_bad!"; // CWE-321: hardcoded key
    printf("Using key: %s\n", key);
}

// ── CWE-330 Use of Insufficiently Random Values ───────────────────────────────
// TRIGGER: rand() for security purposes
void cwe330_weak_random()
{
    srand(12345); // CWE-330: deterministic seed — not cryptographically random
    int token = rand();
    printf("token: %d\n", token);
}

// ── CWE-338 Use of Weak PRNG ──────────────────────────────────────────────────
// TRIGGER: rand() used for session token generation
int cwe338_weak_prng_session_token()
{
    return rand() % 1000000; // CWE-338: weak PRNG for security-sensitive value
}

// ── CWE-326 Inadequate Encryption Strength ────────────────────────────────────
// TRIGGER: short key / weak algorithm comment + stub
void cwe326_weak_encryption()
{
    // CWE-326: simulating use of DES (56-bit key) — inadequate strength
    const char *algorithm = "DES";
    int key_bits = 56; // explicitly weak
    printf("Encrypting with %s, %d-bit key\n", algorithm, key_bits);
}

// ── CWE-327 Use of Broken or Risky Cryptographic Algorithm ───────────────────
// TRIGGER: MD5 / SHA1 used for password hashing
void cwe327_broken_crypto()
{
    // CWE-327: MD5 is cryptographically broken — do not use for integrity/auth
    const char *hash_algo = "MD5";
    printf("Password hashed with: %s\n", hash_algo);
}

// ── CWE-798 Use of Hard-coded Credentials ────────────────────────────────────
// TRIGGER: credentials embedded in source
bool cwe798_hardcoded_credentials(const std::string &user, const std::string &pass)
{
    // CWE-798: hardcoded password in source
    return (user == "admin" && pass == "P@ssw0rd123!");
}

void section_crypto_errors()
{
    printf("\n=== SECTION 6: CRYPTOGRAPHIC ERRORS ===\n");
    cwe321_hardcoded_key();
    cwe330_weak_random();
    cwe338_weak_prng_session_token();
    cwe326_weak_encryption();
    cwe327_broken_crypto();
    cwe798_hardcoded_credentials("admin", "P@ssw0rd123!");
}

// =============================================================================
// SECTION 7 — PATH AND FILE I/O
// =============================================================================

// ── CWE-22 Path Traversal ─────────────────────────────────────────────────────
// TRIGGER: user input used directly in file path
void cwe22_path_traversal(const char *user_filename)
{
    char path[512];
    // CWE-22: no sanitisation — "../../etc/passwd" breaks out of intended dir
    snprintf(path, sizeof(path), "/var/app/uploads/%s", user_filename);
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

// ── CWE-73 External Control of File Name ─────────────────────────────────────
// TRIGGER: filename from external input, no validation
void cwe73_external_filename(const std::string &name)
{
    // CWE-73: externally controlled filename
    std::ofstream ofs(name);
    ofs << "data";
}

// ── CWE-379 Creation of Temporary File in Directory with Insecure Permissions ─
// TRIGGER: predictable temp file name
void cwe379_insecure_temp_file()
{
    char tmpname[64];
    // CWE-379 / CWE-377: predictable name — attacker can pre-create symlink
    snprintf(tmpname, sizeof(tmpname), "/tmp/app_temp_%d.dat", getpid());
    FILE *f = fopen(tmpname, "w");
    if (f) {
        fputs("sensitive data", f);
        fclose(f);
    }
    unlink(tmpname);
}

// ── CWE-732 Incorrect Permission Assignment for Critical Resource ─────────────
// TRIGGER: overly permissive file creation mode
void cwe732_insecure_file_permissions()
{
    int fd = open("/tmp/cwe732_sensitive.dat", O_CREAT | O_WRONLY, 0777); // CWE-732: world-writable
    if (fd >= 0) close(fd);
}

// ── CWE-59 Improper Link Resolution Before File Access ───────────────────────
// TRIGGER: following symlinks without O_NOFOLLOW
void cwe59_symlink_following(const char *path)
{
    // CWE-59: open() without O_NOFOLLOW will follow symlinks
    int fd = open(path, O_RDONLY); // should use O_NOFOLLOW for untrusted paths
    if (fd >= 0) close(fd);
}

void section_path_and_io()
{
    printf("\n=== SECTION 7: PATH AND FILE I/O ===\n");
    cwe22_path_traversal("report.txt");
    cwe73_external_filename("/tmp/cwe73_out.txt");
    cwe379_insecure_temp_file();
    cwe732_insecure_file_permissions();
    cwe59_symlink_following("/tmp/cwe59_test.txt");
}

// =============================================================================
// SECTION 8 — TYPE ERRORS
// =============================================================================

// ── CWE-704 Incorrect Type Conversion or Cast ─────────────────────────────────
// TRIGGER: reinterpret_cast between incompatible pointer types
void cwe704_incorrect_cast()
{
    float f = 3.14f;
    // CWE-704: reinterpret float memory as int — type punning, violates strict aliasing
    int *p = reinterpret_cast<int *>(&f);
    printf("bits: %08X\n", *p);
}

// ── CWE-843 Type Confusion (Access of Resource Using Incompatible Type) ────────
// TRIGGER: base pointer cast to wrong derived type
struct Base843 { virtual void foo() {} virtual ~Base843() {} };
struct DerivedA : Base843 { int a = 1; };
struct DerivedB : Base843 { double d = 2.0; };

void cwe843_type_confusion()
{
    Base843 *b = new DerivedA();
    // CWE-843: treating DerivedA* as DerivedB* — type confusion
    DerivedB *db = static_cast<DerivedB *>(b);
    printf("confused: %f\n", db->d);
    delete b;
}

// ── CWE-686 Function Call with Incorrect Argument Type ───────────────────────
// TRIGGER: passing wrong type to a function
void cwe686_wrong_arg_type()
{
    // CWE-686: printf format expects int but void* passed (on some platforms)
    void *ptr = nullptr;
    printf("value: %d\n", (int)(intptr_t)ptr); // incorrect cast chain
}

// ── CWE-467 Use of sizeof() on Pointer Type ───────────────────────────────────
// TRIGGER: sizeof(pointer) instead of sizeof(*pointer) or element size
void cwe467_sizeof_pointer()
{
    char *buf = (char *)malloc(100);
    if (!buf) return;
    // CWE-467: sizeof(buf) is size of the pointer (8 bytes), not the buffer (100 bytes)
    memset(buf, 0, sizeof(buf));
    free(buf);
}

void section_type_errors()
{
    printf("\n=== SECTION 8: TYPE ERRORS ===\n");
    cwe704_incorrect_cast();
    cwe843_type_confusion();
    cwe686_wrong_arg_type();
    cwe467_sizeof_pointer();
}

// =============================================================================
// SECTION 9 — CONTROL FLOW
// =============================================================================

// ── CWE-252 Unchecked Return Value ────────────────────────────────────────────
// TRIGGER: ignoring return value of security-relevant function
void cwe252_unchecked_return()
{
    // CWE-252: return value of chdir() ignored — current dir may be wrong
    chdir("/tmp");
    // subsequent file operations assume /tmp but may be wrong
}

// ── CWE-391 Unchecked Error Condition ────────────────────────────────────────
// TRIGGER: errno not inspected after system call
void cwe391_unchecked_error()
{
    FILE *f = fopen("/nonexistent/path/file.dat", "r");
    // CWE-391: f is NULL — errno not checked, f used later would crash
    char buf[64];
    if (f) {
        fgets(buf, sizeof(buf), f); // never reached but pattern still flags the missing check above
        fclose(f);
    }
}

// ── CWE-484 Omitted Break Statement in Switch ─────────────────────────────────
// TRIGGER: missing break — fall-through to next case
int cwe484_missing_break(int code)
{
    int result = 0;
    switch (code) {
        case 1:
            result = 10;
            // CWE-484: missing break — falls through to case 2
        case 2:
            result = 20;
            break;
        case 3:
            result = 30;
            break;
    }
    return result;
}

// ── CWE-561 Dead Code ─────────────────────────────────────────────────────────
// TRIGGER: code after unconditional return
int cwe561_dead_code(int x)
{
    if (x > 0) return x;
    return -1;
    printf("This is dead code\n"); // CWE-561: unreachable
    return 0;
}

// ── CWE-570 Expression Always False ──────────────────────────────────────────
// TRIGGER: condition that can never be true
void cwe570_always_false()
{
    unsigned int u = 0;
    if (u < 0) { // CWE-570: unsigned < 0 is always false
        printf("impossible\n");
    }
}

// ── CWE-571 Expression Always True ───────────────────────────────────────────
// TRIGGER: tautological condition
void cwe571_always_true(unsigned int u)
{
    if (u >= 0) { // CWE-571: unsigned >= 0 is always true
        printf("always\n");
    }
}

// ── CWE-617 Reachable Assertion ───────────────────────────────────────────────
// TRIGGER: assert() on input that can realistically be false at runtime
void cwe617_reachable_assert(int user_val)
{
    assert(user_val > 0); // CWE-617: assertion on externally-controlled value — can abort
}

void section_control_flow()
{
    printf("\n=== SECTION 9: CONTROL FLOW ===\n");
    cwe252_unchecked_return();
    cwe391_unchecked_error();
    printf("break result: %d\n", cwe484_missing_break(1));
    cwe561_dead_code(-1);
    cwe570_always_false();
    cwe571_always_true(5);
    cwe617_reachable_assert(1);
}

// =============================================================================
// SECTION 10 — MISCELLANEOUS
// =============================================================================

// ── CWE-20 Improper Input Validation ─────────────────────────────────────────
// TRIGGER: using external data without any validation
void cwe20_improper_input_validation(int user_index)
{
    int arr[10] = {0,1,2,3,4,5,6,7,8,9};
    // CWE-20: user_index not validated before use as array index
    printf("val: %d\n", arr[user_index]);
}

// ── CWE-116 Improper Encoding or Escaping of Output ──────────────────────────
// TRIGGER: raw user data echoed without encoding
void cwe116_improper_output_encoding(const char *user_data)
{
    // CWE-116: user_data echoed without HTML/shell escaping
    printf("Output: %s\n", user_data);
}

// ── CWE-200 Exposure of Sensitive Information ─────────────────────────────────
// TRIGGER: sensitive data written to log/stdout
void cwe200_info_exposure(const char *password)
{
    // CWE-200: password written to log — sensitive info in output
    printf("[LOG] Authenticating with password: %s\n", password);
}

// ── CWE-209 Error Message Information Leakage ─────────────────────────────────
// TRIGGER: full exception/error details exposed to caller
std::string cwe209_verbose_error(const std::string &path)
{
    try {
        std::ifstream f;
        f.exceptions(std::ifstream::failbit);
        f.open(path);
        return "ok";
    } catch (const std::exception &e) {
        // CWE-209: full internal error (including path) returned to caller
        return std::string("Internal error: ") + e.what() + " path=" + path;
    }
}

// ── CWE-259 Use of Hard-coded Password ───────────────────────────────────────
// TRIGGER: hardcoded plaintext password
void cwe259_hardcoded_password()
{
    const char *db_password = "Tr0ub4dor&3"; // CWE-259: hardcoded DB password
    printf("Connecting with password: %s\n", db_password);
}

// ── CWE-319 Cleartext Transmission of Sensitive Information ───────────────────
// TRIGGER: sensitive data sent over unencrypted channel
void cwe319_cleartext_transmission()
{
    // CWE-319: simulated plaintext HTTP transmission of credentials
    const char *payload = "POST http://api.example.com/login user=admin&pass=secret";
    printf("Sending: %s\n", payload);
}

// ── CWE-377 Insecure Temporary File ──────────────────────────────────────────
// TRIGGER: tmpnam() returns predictable name — race condition possible
void cwe377_insecure_tmpfile()
{
    char name[L_tmpnam];
    tmpnam(name); // CWE-377: deprecated, predictable — use mkstemp() instead
    FILE *f = fopen(name, "w");
    if (f) fclose(f);
}

// ── CWE-426 Untrusted Search Path ────────────────────────────────────────────
// TRIGGER: system() or exec* with relative command name
void cwe426_untrusted_search_path()
{
    // CWE-426: "editor" resolved via PATH — attacker-controlled dir in PATH wins
    system("editor /tmp/file.txt");
}

// ── CWE-502 Deserialization of Untrusted Data ─────────────────────────────────
// TRIGGER: external data fed directly into deserialisation routine
void cwe502_unsafe_deserialization(const char *raw_data, size_t len)
{
    // CWE-502: raw_data from network treated as trusted struct
    struct Config { int version; char name[64]; } cfg;
    if (len >= sizeof(cfg)) {
        memcpy(&cfg, raw_data, sizeof(cfg)); // no validation of content
        printf("version: %d, name: %s\n", cfg.version, cfg.name);
    }
}

// ── CWE-676 Use of Potentially Dangerous Function ────────────────────────────
// TRIGGER: gets() — no bounds on input length
void cwe676_dangerous_function()
{
    char buf[64];
    // CWE-676 / CWE-242: gets() cannot limit input length — always overflows
    // gets(buf); // Commented to avoid CI crash but pattern is flagged by SAST
    (void)buf;
    printf("gets() would be called here\n");
}

// ── CWE-703 Improper Check or Handling of Exceptional Conditions ──────────────
// TRIGGER: exception silently swallowed
void cwe703_swallowed_exception()
{
    try {
        throw std::runtime_error("critical failure");
    } catch (...) {
        // CWE-703: exception silently ignored — failure state hidden
    }
}

// ── CWE-754 Improper Check for Unusual or Exceptional Conditions ──────────────
// TRIGGER: malloc result used without null check
void cwe754_unchecked_malloc()
{
    int *p = (int *)malloc(sizeof(int) * 1000000000LL); // CWE-754: may return NULL — not checked
    p[0] = 1; // potential null deref
    free(p);
}

// ── CWE-805 Buffer Access with Incorrect Length Value ─────────────────────────
// TRIGGER: length argument larger than destination
void cwe805_incorrect_length()
{
    char src[8] = "hello";
    char dst[4];
    // CWE-805: length argument (8) exceeds destination size (4)
    memcpy(dst, src, 8);
}

// ── CWE-824 Access of Uninitialized Pointer ───────────────────────────────────
// TRIGGER: pointer used before assignment
void cwe824_uninit_pointer()
{
    char *p; // CWE-824: p is uninitialized
    printf("ptr value: %p\n", (void *)p);
}

// ── CWE-908 Use of Uninitialized Resource ────────────────────────────────────
// TRIGGER: local variable read before write
int cwe908_uninit_variable()
{
    int x; // CWE-908: x is never assigned before use
    return x + 1;
}

// ── CWE-131 Incorrect Calculation of Buffer Size ─────────────────────────────
// TRIGGER: off-by-one in allocation — no room for null terminator
void cwe131_incorrect_buffer_size(const char *str)
{
    size_t len = strlen(str);
    char *buf = (char *)malloc(len); // CWE-131: should be len+1 for null terminator
    if (!buf) return;
    strcpy(buf, str); // writes past end
    free(buf);
}

// ── CWE-170 Improper Null Termination ────────────────────────────────────────
// TRIGGER: strncpy does not guarantee null termination
void cwe170_improper_null_termination(const char *src)
{
    char buf[8];
    // CWE-170: strncpy may not null-terminate if src >= buf size
    strncpy(buf, src, sizeof(buf));
    printf("%s\n", buf); // may read past end of buf
}

// ── CWE-14 Compiler Removal of Code to Clear Buffers ─────────────────────────
// TRIGGER: memset of sensitive buffer that may be optimised away
void cwe14_compiler_optimisation_clears_memset()
{
    char password[64];
    strcpy(password, "SuperSecretPassword");
    // ... use password ...
    memset(password, 0, sizeof(password)); // CWE-14: compiler may elide this — use memset_s / explicit_bzero
}

void section_miscellaneous()
{
    printf("\n=== SECTION 10: MISCELLANEOUS ===\n");
    cwe20_improper_input_validation(5);
    cwe116_improper_output_encoding("user_data");
    cwe200_info_exposure("hunter2");
    printf("%s\n", cwe209_verbose_error("/etc/shadow").c_str());
    cwe259_hardcoded_password();
    cwe319_cleartext_transmission();
    cwe377_insecure_tmpfile();
    cwe426_untrusted_search_path();
    char dummy[128] = {};
    cwe502_unsafe_deserialization(dummy, sizeof(dummy));
    cwe676_dangerous_function();
    cwe703_swallowed_exception();
    cwe131_incorrect_buffer_size("hello");
    cwe170_improper_null_termination("toolong!");
    cwe14_compiler_optimisation_clears_memset();
    cwe824_uninit_pointer();
    (void)cwe908_uninit_variable();
}

// =============================================================================
// MAIN
// =============================================================================

int main()
{
    printf("================================================================\n");
    printf("  CWE TEST HARNESS — SonarQube SAST Evaluation\n");
    printf("  Target: 60+ CWE weakness patterns\n");
    printf("  *** TEST / ANALYSIS USE ONLY — DO NOT EXECUTE ***\n");
    printf("================================================================\n");

    section_memory_safety();
    section_injection();
    section_numeric();
    section_concurrency();
    section_resource_mgmt();
    section_crypto_errors();
    section_path_and_io();
    section_type_errors();
    section_control_flow();
    section_miscellaneous();

    printf("\n================================================================\n");
    printf("  Analysis complete.\n");
    printf("================================================================\n");
    return 0;
}
