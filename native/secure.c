/* Safe equivalent. In production, external metadata must be size-limited. */
#include <stdio.h>
#include <string.h>
int parse_event_tag(const char *tag) {
    char buffer[16];
    if (!tag || strlen(tag) >= sizeof buffer) {
        fputs("Rejected oversized event tag\n", stderr);
        return -1;
    }
    snprintf(buffer, sizeof buffer, "%s", tag);
    return (int)strlen(buffer);
}
/* The CLI is excluded when building the shared library for DOLOS. */
#ifndef DOLOS_LIBRARY
int main(int argc, char **argv) {
    if (argc != 2) {fprintf(stderr,"Usage: %s <tag>\n",argv[0]);return 2;}
    int size = parse_event_tag(argv[1]);
    if (size < 0) return 1;
    printf("Accepted tag length: %d\n",size);
    return 0;
}

#endif
