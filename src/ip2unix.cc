// SPDX-License-Identifier: LGPL-3.0-only
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <string>
#include <unistd.h>

#include "rules.hh"

extern char **environ;

static bool run_preload(char *argv[])
{
    char self[PATH_MAX], *preload;
    ssize_t len;

    if ((len = readlink("/proc/self/exe", self, sizeof(self) - 1)) == -1) {
        perror("readlink(\"/proc/self/exe\")");
        return false;
    }

    self[len] = '\0';

    if ((preload = getenv("LD_PRELOAD")) != nullptr && *preload != '\0') {
        std::string new_preload = std::string(self) + ":" + preload;
        setenv("LD_PRELOAD", new_preload.c_str(), 1);
    } else {
        setenv("LD_PRELOAD", self, 1);
    }

    setenv("IP2UNIX_RULE_FILE", argv[0], 1);
    argv++;

    if (execvpe(argv[0], argv, environ) == -1) {
        std::string err = "execvpe(\"" + std::string(argv[0]) + "\")";
        perror(err.c_str());
    }

    return false;
}

static void print_usage(char *prog, FILE *fp)
{
    fprintf(fp, "Usage: %s [options] RULEFILE PROGRAM [ARGS...]\n", prog);
    fprintf(fp, "       %s -c [options] RULEFILE\n\n", prog);
    fputs("Turn IP sockets into Unix domain sockets for PROGRAM\n", fp);
    fputs("according to the rules specified by the JSON file given\n", fp);
    fputs("by RULEFILE.\n\nOptions:\n", fp);
    fputs("  -h, --help       Show this usage\n",              fp);
    fputs("  -c, --check      Validate rules and exit\n",      fp);
    fputs("  -p, --print      Print out the table of rules\n", fp);
}

int main(int argc, char *argv[])
{
    int c;
    char *self = argv[0];

    bool check_only = false;
    bool show_rules = false;

    static struct option options[] = {
        {"help", no_argument, 0, 'h'},
        {"check", no_argument, 0, 'c'},
        {"print", no_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "hcp", options, NULL)) != -1) {
        switch (c) {
            case 'h':
                print_usage(self, stdout);
                return EXIT_SUCCESS;

            case 'c':
                check_only = true;
                break;

            case 'p':
                show_rules = true;
                break;

            default:
                print_usage(self, stderr);
                return EXIT_FAILURE;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0 || (check_only && argc != 1)) {
        fprintf(stderr, "%s: Rule file is missing.\n\n", self);
        print_usage(self, stderr);
        return EXIT_FAILURE;
    }

    std::optional<std::vector<UdsmapRule>> rules = parse_rules(argv[0]);

    if (!rules)
        return EXIT_FAILURE;
    if (show_rules)
        print_rules(rules.value());
    if (check_only)
        return EXIT_SUCCESS;

    if (argc == 1) {
        fprintf(stderr, "%s: No program to execute specified.\n", self);
        print_usage(self, stderr);
    } else {
        run_preload(argv);
    }

    return EXIT_FAILURE;
}
