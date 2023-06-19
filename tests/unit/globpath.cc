#include <stdexcept>
#include <memory>

#include "globpath.hh"

#define SUCCESS(pat, path) \
    if (!globpath(pat, path)) \
        throw std::runtime_error(#pat " should have matched " #path \
                                 " but did not match.");

#define NOMATCH(pat, path) \
    if (globpath(pat, path)) \
        throw std::runtime_error(#pat " should not have matched " #path \
                                 " but resulted in a match.");

int main(void)
{
    SUCCESS("!#%+,-./01234567889", "!#%+,-./01234567889");
    SUCCESS(":;=@ABCDEFGHIJKLMNO", ":;=@ABCDEFGHIJKLMNO");
    SUCCESS("PQRSTUVWXYZ]abcdefg", "PQRSTUVWXYZ]abcdefg");
    SUCCESS("hijklmnopqrstuvwxyz", "hijklmnopqrstuvwxyz");
    SUCCESS("^_{}~",               "^_{}~");

    SUCCESS("\\\"\\$\\&\\'\\(\\)", "\"$&'()");
    SUCCESS("\\*\\?\\[\\\\\\`\\|", "*?[\\`|");
    SUCCESS("\\<\\>",              "<>");

    SUCCESS("[?*[][?*[][?*[]",     "?*[");
    SUCCESS("?/b",                 "a/b");

    NOMATCH("a?b",                 "a/b");
    SUCCESS("a/?",                 "a/b");
    NOMATCH("?/b",                 "aa/b");
    NOMATCH("a?b",                 "aa/b");
    NOMATCH("a/?",                 "a/bbb");
    NOMATCH("a/?",                 "a/bb");

    NOMATCH("[abc]",               "abc");
    NOMATCH("[abc]",               "x");
    SUCCESS("[abc]",               "a");
    SUCCESS("[[abc]",              "[");
    SUCCESS("[][abc]",             "a");
    SUCCESS("[]a]]",               "a]");

    NOMATCH("[!abc]",              "xyz");
    SUCCESS("[!abc]",              "x");
    NOMATCH("[!abc]",              "a");

    SUCCESS("[][abc]",             "]");
    NOMATCH("[][abc]",             "abc]");
    NOMATCH("[][]abc",             "[]abc");
    NOMATCH("[!]]",                "]");
    NOMATCH("[!]a]",               "aa]");
    SUCCESS("[!a]",                "]");
    SUCCESS("[!a]]",               "]]");

    SUCCESS("[a-c]",               "a");
    SUCCESS("[a-c]",               "b");
    SUCCESS("[a-c]",               "c");
    NOMATCH("[b-c]",               "a");
    NOMATCH("[b-c]",               "d");
    NOMATCH("[a-c]",               "B");
    NOMATCH("[A-C]",               "b");
    NOMATCH("[a-c]",               "");
    NOMATCH("[a-ca-z]",            "as");

    NOMATCH("[c-a]",               "a");
    NOMATCH("[c-a]",               "c");

    SUCCESS("[a-c0-9]",            "a");
    NOMATCH("[a-c0-9]",            "d");
    NOMATCH("[a-c0-9]",            "B");

    SUCCESS("[-a]",                "-");
    NOMATCH("[-b]",                "a");
    NOMATCH("[!-a]",               "-");
    SUCCESS("[!-b]",               "a");
    SUCCESS("[a-c-0-9]",           "-");
    SUCCESS("[a-c-0-9]",           "b");
    NOMATCH("a[0-9-a]",            "a:");
    SUCCESS("a[09-a]",             "a:");

    SUCCESS("*",                   "");
    SUCCESS("*",                   "asd/sdf");

    SUCCESS("[a-c][a-z]",          "as");
    SUCCESS("??",                  "as");

    NOMATCH("as*df",               "asd/sdf");
    NOMATCH("as*",                 "asd/sdf");
    SUCCESS("*df",                 "asd/sdf");
    NOMATCH("as*dg",               "asd/sdf");
    SUCCESS("as*df",               "asdf");
    NOMATCH("as*df?",              "asdf");
    SUCCESS("as*??",               "asdf");
    SUCCESS("a*???",               "asdf");
    SUCCESS("*????",               "asdf");
    SUCCESS("????*",               "asdf");
    SUCCESS("??*?",                "asdf");

    SUCCESS("/",                   "/");
    SUCCESS("/*",                  "/");
    SUCCESS("*/",                  "/");
    NOMATCH("/?",                  "/");
    NOMATCH("?/",                  "/");
    SUCCESS("?",                   ".");
    NOMATCH("??",                  "/.");
    NOMATCH("[!a-c]",              "/");
    SUCCESS("[!a-c]",              ".");

    SUCCESS("/",                   "/");
    SUCCESS("//",                  "//");
    SUCCESS("/*",                  "/.a");
    SUCCESS("/?a",                 "/.a");
    SUCCESS("/[!a-z]a",            "/.a");
    SUCCESS("*/?b",                ".a/.b");
    SUCCESS("/*/?b",               "/.a/.b");

    NOMATCH("?",                   "/");
    SUCCESS("*",                   "/");
    NOMATCH("a?b",                 "a/b");
    NOMATCH("/*b",                 "/.a/.b");

    SUCCESS("\\/\\$",              "/$");
    SUCCESS("\\/\\[",              "/[");
    SUCCESS("\\/[",                "/[");
    SUCCESS("\\/\\[]",             "/[]");

    SUCCESS(".*",                  ".asd");
    SUCCESS("*",                   "/.asd");
    SUCCESS("/*/?*f",              "/as/.df");
    SUCCESS(".[!a-z]*",            "..asd");

    SUCCESS("*",                   ".asd");
    SUCCESS("?asd",                ".asd");
    SUCCESS("[!a-z]*",             ".asd");

    SUCCESS("/.",                  "/.");
    SUCCESS("/.*/.*",              "/.a./.b.");
    SUCCESS("/.??/.??",            "/.a./.b.");

    SUCCESS("*",                   "/.");
    SUCCESS("/*",                  "/.");
    SUCCESS("/?",                  "/.");
    SUCCESS("/[!a-z]",             "/.");
    SUCCESS("/*/*",                "/a./.b.");
    SUCCESS("/??/???",             "/a./.b.");

    NOMATCH("foo*[abc]z",          "foobar");
    SUCCESS("foo*[abc][xyz]",      "foobaz");
    SUCCESS("foo?*[abc][xyz]",     "foobaz");
    SUCCESS("foo?*[abc][x/yz]",    "fooba[x/yz]");
    NOMATCH("foo?*[abc]/[xyz]",    "foobaz");
    NOMATCH("a/",                  "a");
    NOMATCH("a",                   "a/");
    NOMATCH("/a",                  "//a");
    NOMATCH("//a",                 "/a");
    SUCCESS("[a-]z",               "az");
    SUCCESS("[ab-]z",              "bz");
    NOMATCH("[ab-]z",              "cz");
    SUCCESS("[ab-]z",              "-z");
    SUCCESS("[-a]z",               "az");
    SUCCESS("[-ab]z",              "bz");
    NOMATCH("[-ab]z",              "cz");
    SUCCESS("[-ab]z",              "-z");
    SUCCESS("[\\\\-a]",            "\\");
    SUCCESS("[\\\\-a]",            "_");
    SUCCESS("[\\\\-a]",            "a");
    NOMATCH("[\\\\-a]",            "-");
    NOMATCH("[\\]-a]",             "\\");
    SUCCESS("[\\]-a]",             "_");
    SUCCESS("[\\]-a]",             "a");
    SUCCESS("[\\]-a]",             "]");
    NOMATCH("[\\]-a]",             "-");
    NOMATCH("[!\\\\-a]",           "\\");
    NOMATCH("[!\\\\-a]",           "_");
    NOMATCH("[!\\\\-a]",           "a");
    SUCCESS("[!\\\\-a]",           "-");
    SUCCESS("[\\!-]",              "!");
    SUCCESS("[\\!-]",              "-");
    NOMATCH("[\\!-]",              "\\");
    SUCCESS("[Z-\\\\]",            "Z");
    SUCCESS("[Z-\\\\]",            "[");
    SUCCESS("[Z-\\\\]",            "\\");
    NOMATCH("[Z-\\\\]",            "-");
    SUCCESS("[Z-\\]]",             "Z");
    SUCCESS("[Z-\\]]",             "[");
    SUCCESS("[Z-\\]]",             "\\");
    SUCCESS("[Z-\\]]",             "]");
    NOMATCH("[Z-\\]]",             "-");

    SUCCESS("**/foo",              "foo");
    SUCCESS("**/foo",              "xxx/foo");
    SUCCESS("**/foo",              "y/xxx/foo");
    SUCCESS("**/foo",              "/y/xxx/foo");
    SUCCESS("a/**/foo",            "a/b/cde/foo");
    SUCCESS("a/**/foo",            "a/foo");
    NOMATCH("a**/foo",             "a/b/foo");
    SUCCESS("**",                  "xxx");
    SUCCESS("**",                  "xxx/");
    SUCCESS("**/*",                "xxx/");
    SUCCESS("**/*",                "xxx/yyy");
    SUCCESS("**/*",                "yyy");
    SUCCESS("a/**b/ccc",           "a/b/ccc");
    SUCCESS("a/b**/ccc",           "a/b/ccc");
    NOMATCH("a/b**/ccc",           "a/xxx/ccc");
    NOMATCH("a/**b/ccc",           "a/xxx/ccc");
    SUCCESS("b/**",                "b/xxx");
    SUCCESS("b/**",                "b/xxx/yyy");
    NOMATCH("b/****/c",            "b/xxx/yyy/c");
    NOMATCH("b/***/c",             "b/xxx/yyy/c");
    NOMATCH("b/*/c",               "b/xxx/yyy/c");
    NOMATCH("a**b",                "aaa/bbb");
    SUCCESS("**/foo/**/bar",       "foo/a/b/bar");
    SUCCESS("**/foo/**/bar",       "a/b/foo/c/d/bar");
    SUCCESS("**/foo/**/bar",       "foo/bar");
    SUCCESS("**/foo/aaa/**/bar",   "/a/b/foo/aaa/bar/foo/bar");
    NOMATCH("**/foo/aaa/**/bar",   "/a/b/foo/bbb/bar/foo/bar");
    SUCCESS("a/**/**/b",           "a/b");
    SUCCESS("a/**/**/b",           "a/x/b");
    SUCCESS("a/**/**/b",           "a/x/y/b");

    SUCCESS("foo[a/b]bar",         "foo[a/b]bar");
    SUCCESS("foo\\[a/b]bar",       "foo[a/b]bar");

    SUCCESS("\\*\\?[aaaa",         "*?[aaaa");
    NOMATCH("\\*\\?[aaaa",         "*?[aaa");
    NOMATCH("\\*\\?[aaaa",         "*?[");
    SUCCESS("\\*\\?[a-",           "*?[a-");

    return 0;
}
