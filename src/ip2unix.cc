// SPDX-License-Identifier: LGPL-3.0-only
#include <getopt.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cctype>
#include <fstream>
#include <optional>
#include <vector>

#include "rules.hh"
#include "serial.hh"

extern char **environ;

extern "C" const char *__ip2unix__(void);

static std::optional<std::string> get_preload_libpath(void)
{
    Dl_info info;

    if (dladdr(reinterpret_cast<void*>(__ip2unix__), &info) < 0) {
        perror("dladdr");
        return std::nullopt;
    }

    return std::string(info.dli_fname);
}

static bool run_preload(std::vector<Rule> &rules, char *argv[])
{
    const char *libversion;
    char *preload;
    std::optional<std::string> libpath;

    libversion = __ip2unix__();

    if (!(libpath = get_preload_libpath())) {
        return false;
    }

    if (strcmp(libversion, VERSION) != 0) {
        fprintf(stderr, "Version mismatch between preload library (%s) and"
                        " wrapper program (%s).\n", libversion, VERSION);
        return false;
    }

    if ((preload = getenv("LD_PRELOAD")) != nullptr && *preload != '\0') {
        std::string new_preload = libpath.value() + ":" + preload;
        setenv("LD_PRELOAD", new_preload.c_str(), 1);
    } else {
        setenv("LD_PRELOAD", libpath.value().c_str(), 1);
    }

    setenv("__IP2UNIX_RULES", serialise(rules).c_str(), 1);

    if (execvpe(argv[0], argv, environ) == -1) {
        std::string err = "execvpe(\"" + std::string(argv[0]) + "\")";
        perror(err.c_str());
    }

    return false;
}

#define PROG "PROGRAM [ARGS...]"
#define COMMON "[-v...] [-p]"
#define RULE_ARGS "{-r RULE | -f FILE} [-r RULE | -f FILE]..."
#define RULE_DOC_URL "https://github.com/nixcloud/ip2unix/blob/v" VERSION \
                     "/README.adoc#rule-specification"

static void print_usage(char *prog, FILE *fp)
{
    fprintf(fp, "Usage: %s " COMMON " " RULE_ARGS " " PROG "\n", prog);
    fprintf(fp, "       %s " COMMON " -c " RULE_ARGS "\n", prog);
    fprintf(fp, "       %s -h\n", prog);
    fprintf(fp, "       %s --version\n", prog);
    fputs("\nTurn IP sockets into Unix domain sockets for PROGRAM\n", fp);
    fputs("according to the rules specified via either one or more\n", fp);
    fputs("FILE options or directly via one or more RULE arguments.\n", fp);
    fputs("\nOptions:\n", fp);
    fputs("  -h, --help        Show this usage\n",                        fp);
    fputs("      --version     Output version information and exit\n",    fp);
    fputs("  -c, --check       Validate rules and exit\n",                fp);
    fputs("  -p, --print       Print out the table of rules\n",           fp);
    fputs("  -f, --file=FILE   Read newline-separated rules from FILE\n", fp);
    fputs("  -r, --rule        A single rule\n",                          fp);
    fputs("  -v, --verbose     Increase level of verbosity\n",            fp);
#ifdef WITH_MANPAGE
    fputs("\nSee ip2unix(1) for details about specifying rules.\n",       fp);
#else
    fputs("\nSee " RULE_DOC_URL " for details about specifying rules.\n", fp);
#endif
}

static void print_version(void)
{
    fputs("ip2unix " VERSION "\n"
          "Copyright (C) 2018 aszlig\n"
          "This program is free software; you may redistribute it under\n"
          "the terms of the GNU Lesser General Public License version 3.\n",
          stdout);
}

static void warn_deprecated_rules_file_long_opt(void)
{
    fputs("The use of the --rules-file option is deprecated and the option"
          " will be removed in ip2unix version 3.0. Furthermore, YAML will no"
          " longer be supported for rule specification and the new --file"
          " option simply takes a file with a list of newline-separated rules"
          " as specified via the -r/--rule option.", stderr);
}

static void warn_deprecated_yaml_data(void)
{
    fputs("The use of -F/--rules-data option is deprecated and it will be"
          " removed in ip2unix version 3. Please use the -r/--rule option"
          " instead.\n", stderr);
}

static void warn_deprecated_yaml_file(std::string &filename)
{
    fprintf(stderr, "The rule file '%s' contains YAML data, which will no"
            " longer be supported in ip2unix version 3. Please use a list of"
            " newline-separated rules as specified via the -r/--rule option.",
            filename.c_str());
}

static bool push_rule_args_from_file(std::string &filename,
                                     std::vector<std::string> &rule_args)
{
    std::ifstream input(filename);
    std::string line;

    if (!input.is_open()) {
        fprintf(stderr, "Error opening rule file '%s': %s\n",
                filename.c_str(), strerror(errno));
        return false;
    }

    while (std::getline(input, line)) {
        // Remove all leading whitespace characters
        auto to_erase = std::find_if(
            line.begin(), line.end(), [](int c) { return !std::isspace(c); }
        );
        line.erase(line.begin(), to_erase);

        if (line.empty() || line[0] == '#')
            continue;

        rule_args.push_back(line);
    }

    if (input.bad()) {
        fprintf(stderr, "Error reading rule file '%s': %s\n",
                filename.c_str(), strerror(errno));
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    int c;
    char *self = argv[0];

    bool check_only = false;
    bool show_rules = false;
    unsigned int verbosity = 0;

    // TODO: Remove in version 3.0.
    bool show_warn_deprecated_rules_file_long_opt = false;
    bool show_warn_deprecated_yaml_data = false;

    static struct option lopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {"check", no_argument, nullptr, 'c'},
        {"print", no_argument, nullptr, 'p'},
        {"rule", required_argument, nullptr, 'r'},
        {"file", required_argument, nullptr, 'f'},
        {"verbose", no_argument, nullptr, 'v'},

        // TODO: Remove in version 3.0.
        {"rules-file", required_argument, nullptr, 'y'},
        {"rules-data", required_argument, nullptr, 'F'},

        {nullptr, 0, nullptr, 0}
    };

    std::optional<std::string> rulefile = std::nullopt;
    std::optional<std::string> ruledata = std::nullopt;
    std::vector<std::string> rule_args;

    while ((c = getopt_long(argc, argv, "+hcpr:f:F:v",
                            lopts, nullptr)) != -1) {
        switch (c) {
            case 'h':
                print_usage(self, stdout);
                return EXIT_SUCCESS;

            case 'V':
                print_version();
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

            case 'y':
                show_warn_deprecated_rules_file_long_opt = true;
                [[fallthrough]];
            case 'f':
                rulefile = std::string(optarg);
                if (is_yaml_rule_file(*rulefile))
                    warn_deprecated_yaml_file(*rulefile);
                else if (push_rule_args_from_file(*rulefile, rule_args))
                    // XXX: This is to make sure that when we use the new rule
                    //      file format we can use multiple -f options.
                    // TODO: Remove this in version 3.0 when dropping YAML
                    //       support.
                    rulefile = std::nullopt;
                else
                    return EXIT_FAILURE;
                break;

            case 'F':
                show_warn_deprecated_yaml_data = true;
                ruledata = std::string(optarg);
                break;

            case 'v':
                verbosity++;
                break;

            default:
                fputc('\n', stderr);
                print_usage(self, stderr);
                return EXIT_FAILURE;
        }
    }

    // TODO: Remove in version 3.0.
    if (show_warn_deprecated_rules_file_long_opt)
        warn_deprecated_rules_file_long_opt();
    if (show_warn_deprecated_yaml_data)
        warn_deprecated_yaml_data();

    if (!rule_args.empty() && (rulefile || ruledata)) {
        fprintf(stderr, "%s: Can't specify both direct rules and a rule"
                        " file.\n\n", self);
        print_usage(self, stderr);
        return EXIT_FAILURE;
    }

    if (rulefile && ruledata) {
        fprintf(stderr, "%s: Can't use a rule file path and inline rules"
                        " at the same time.\n\n", self);
        print_usage(self, stderr);
        return EXIT_FAILURE;
    }

    std::vector<Rule> rules;

    if (!rule_args.empty()) {
        size_t rulepos = 0;
        for (auto arg : rule_args) {
            auto result = parse_rule_arg(++rulepos, arg);
            if (result)
                rules.push_back(result.value());
            else
                return EXIT_FAILURE;
        }
    } else if (rulefile) {
        auto result = parse_rules(rulefile.value(), true);
        if (!result) return EXIT_FAILURE;
        rules = result.value();
    } else if (ruledata) {
        auto result = parse_rules(ruledata.value(), false);
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
        if (verbosity > 0) {
            setenv("__IP2UNIX_VERBOSITY",
                   std::to_string(verbosity).c_str(), 1);
        }
        run_preload(rules, argv);
    } else {
        fprintf(stderr, "%s: No program to execute specified.\n", self);
        print_usage(self, stderr);
    }

    return EXIT_FAILURE;
}
