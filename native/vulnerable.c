/* DELIBERATELY VULNERABLE: isolated memory-safety teaching example only.
 * Build with -fsanitize=address, run on test input, never process real files. */
#include <stdio.h>
#include <string.h>
int parse_event_tag(const char *tag) {
    char buffer[16];
    strcpy(buffer, tag);  /* CWE-120: missing bounds check */
    return (int)strlen(buffer);
}
int main(int argc, char **argv) {
    if (argc != 2) {fprintf(stderr, "Usage: %s <tag>\n", argv[0]);return 2;}
    printf("Tag length: %d\n", parse_event_tag(argv[1]));
    return 0;
}
