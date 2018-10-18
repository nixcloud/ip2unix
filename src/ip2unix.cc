// SPDX-License-Identifier: LGPL-3.0-only
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <string>
#include <unistd.h>

#include "rules.hh"

extern char **environ;

static bool run_preload(std::vector<Rule> &rules, char *argv[])
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

    std::string encoded = encode_rules(rules);

    setenv("__IP2UNIX_RULES", encoded.c_str(), 1);

    if (execvpe(argv[0], argv, environ) == -1) {
        std::string err = "execvpe(\"" + std::string(argv[0]) + "\")";
        perror(err.c_str());
    }

    return false;
}

#define PROG_ARGS "PROGRAM [ARGS...]"

static void print_usage(char *prog, FILE *fp)
{
    fprintf(fp, "Usage: %s [-p] -f RULES_FILE        " PROG_ARGS "\n", prog);
    fprintf(fp, "       %s [-p] -r RULE [-r RULE]... " PROG_ARGS "\n", prog);
    fprintf(fp, "       %s [-p] -c -f RULES_FILE\n", prog);
    fprintf(fp, "       %s [-p] -c -r RULE\n", prog);
    fprintf(fp, "       %s -h\n", prog);
    fputs("\nTurn IP sockets into Unix domain sockets for PROGRAM\n", fp);
    fputs("according to the rules specified by either the YAML file\n", fp);
    fputs("given by RULES_FILE or rules specified via one or more RULE\n", fp);
    fputs("arguments.\n", fp);
    fputs("\nOptions:\n", fp);
    fputs("  -h, --help       Show this usage\n",              fp);
    fputs("  -c, --check      Validate rules and exit\n",      fp);
    fputs("  -p, --print      Print out the table of rules\n", fp);
    fputs("  -f, --rule-file  YAML/JSON file containing the rules\n", fp);
    fputs("  -r, --rule       A single rule\n", fp);
    fputs("\nSee ip2unix(1) for details about specifying rules.\n", fp);
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
        {"rule", required_argument, 0, 0},
        {"rule-file", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    std::optional<std::string> rulefile = std::nullopt;
    std::vector<std::string> rule_args;

    while ((c = getopt_long(argc, argv, "+hcpr:f:", options, NULL)) != -1) {
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

            case 'r':
                rule_args.push_back(optarg);
                break;

            case 'f':
                rulefile = std::string(optarg);
                break;

            default:
                print_usage(self, stderr);
                return EXIT_FAILURE;
        }
    }

    if (!rule_args.empty() && rulefile) {
        fprintf(stderr, "%s: Can't specify both direct rules and a rule"
                        " file.\n\n", self);
        print_usage(self, stderr);
        return EXIT_FAILURE;
    }

    std::vector<Rule> rules;

    if (!rule_args.empty()) {
        for (auto arg : rule_args) {
            auto result = parse_rule_arg(arg);
            if (result)
                rules.push_back(result.value());
            else
                return EXIT_FAILURE;
        }
    } else if (rulefile) {
        auto result = parse_rules(rulefile.value(), true);
        if (!result) return EXIT_FAILURE;
        rules = result.value();
    } else {
        fprintf(stderr, "%s: You need to either specify a rule file with '-f'"
                        " or directly specify rules via '-r'.\n\n", self);
        print_usage(self, stderr);
        return EXIT_FAILURE;
    }

    if (show_rules)
        print_rules(rules, check_only ? std::cout : std::cerr);
    if (check_only)
        return EXIT_SUCCESS;

    argc -= optind;
    argv += optind;

    if (argc >= 1) {
        run_preload(rules, argv);
    } else {
        fprintf(stderr, "%s: No program to execute specified.\n", self);
        print_usage(self, stderr);
    }

    return EXIT_FAILURE;
}
