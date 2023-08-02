// SPDX-License-Identifier: LGPL-3.0-only
#include <stddef.h>
#include <optional>
#include <string>
#include <string_view>

#include "globpath.hh"

enum class MatchResult {
    Matched,
    NotMatched,
    EndOfInput,
    Invalid,
    GotSlash,
    GotRecursive,
};

class GlobPath {
    std::string_view pattern;
    std::string_view path;
    const size_t patlen;
    size_t pathlen;

    MatchResult match_cclass(size_t*, const char&);
    MatchResult match_fixed(size_t*, size_t*);
    MatchResult match_norec(size_t*, size_t*);

    std::optional<size_t> skip_component(const size_t&);

    public:
        GlobPath(const std::string&, const std::string&);
        bool match(void);
};

GlobPath::GlobPath(const std::string &needle, const std::string &haystack)
    : pattern(needle)
    , path(haystack)
    , patlen(needle.size())
    , pathlen(haystack.size())
{
}

MatchResult GlobPath::match_cclass(size_t *pattern_pos, const char &pathchar)
{
    bool negate = false;
    size_t nextpat = *pattern_pos + 1;

    if (nextpat >= this->patlen)
        return MatchResult::Invalid;

    if (this->pattern[nextpat] == '!') {
        negate = true;
        if (++nextpat >= this->patlen)
            return MatchResult::Invalid;
    }

    bool found = false;
    std::optional<char> rstart;

    do {
        if (nextpat >= this->patlen || this->pattern[nextpat] == '/') {
            return MatchResult::Invalid;
        } else if (this->pattern[nextpat] == '\\') {
            if (++nextpat >= this->patlen)
                return MatchResult::Invalid;
        }

        if (rstart) {
            bool mstart = *rstart <= pathchar;
            bool mend = this->pattern[nextpat] >= pathchar;
            if (mstart && mend)
                found = true;
            rstart = std::nullopt;
        } else if (nextpat + 1 < this->patlen &&
                   this->pattern[nextpat + 1] == '-') {
            rstart = pattern[nextpat];
            nextpat++;
        } else if (this->pattern[nextpat] == pathchar) {
            found = true;
        }
        nextpat++;
    } while (this->pattern[nextpat] != ']');

    // Range has ended preliminary (like eg. "[a-]") so we need to match the
    // start character and the dash.
    if (rstart && (pathchar == *rstart || pathchar == '-'))
        found = true;

    *pattern_pos = nextpat;
    return (negate ? !found : found)
         ? MatchResult::Matched
         : MatchResult::NotMatched;
}

MatchResult GlobPath::match_fixed(size_t *pattern_pos, size_t *path_pos)
{
    size_t patpos = *pattern_pos;
    size_t pathpos = *path_pos;

    while (patpos < this->patlen) {
        const char &p = this->pattern[patpos];

        if (p == '*') {
            *pattern_pos = patpos;
            *path_pos = pathpos;
            return MatchResult::Matched;
        } else if (pathpos >= this->pathlen) {
            return MatchResult::EndOfInput;
        } else if (this->path[pathpos] == '/') {
            // Handle escaped forward slash.
            if (this->pattern[patpos] == '\\' && patpos + 1 < this->patlen) {
                if (this->pattern[patpos + 1] == '/')
                    patpos++;
            }
            *pattern_pos = patpos;
            *path_pos = pathpos;
            return MatchResult::GotSlash;
        } else if (p == '[') {
            MatchResult res = this->match_cclass(&patpos, this->path[pathpos]);
            if (res == MatchResult::NotMatched)
                return MatchResult::NotMatched;
        } else if (p != '?') {
            if (p == '\\') {
                if (++patpos >= this->patlen)
                    return MatchResult::NotMatched;
            }
            if (this->pattern[patpos] != this->path[pathpos])
                return MatchResult::NotMatched;
        }

        patpos++;
        pathpos++;
    }

    *pattern_pos = patpos;
    *path_pos = pathpos;
    return pathpos >= this->pathlen
         ? MatchResult::Matched
         : MatchResult::NotMatched;
}

MatchResult GlobPath::match_norec(size_t *pattern_pos, size_t *path_pos)
{
    size_t patpos = *pattern_pos;
    size_t pathpos = *path_pos;
    size_t last_slash = *pattern_pos;

    while (patpos < this->patlen) {
        if (this->pattern[patpos] == '*') {
            size_t anum;
            // Eat up all consecutive "any string" wildcard characters.
            for (anum = 0; this->pattern[patpos] == '*'; ++anum) {
                // If the wildcard is the last character in pattern, anything
                // from the rest of path will match.
                if (patpos >= this->patlen) {
                    *pattern_pos = patpos;
                    *path_pos = pathpos;
                    return MatchResult::Matched;
                } else {
                    patpos++;
                }
            }

            // If the number of asterisks is two followed by a slash, we need
            // to do recursive globbing, like eg. "a/**/b" or "**/foo".
            bool is_slash = this->pattern[patpos] == '/';
            if (anum == 2 && last_slash + 2 == patpos && is_slash) {
                *pattern_pos = patpos + 1;
                *path_pos = pathpos;
                return MatchResult::GotRecursive;
            }

            for (;;) {
                MatchResult result = this->match_fixed(&patpos, &pathpos);
                // If the fixed match fails, we need to skip one character and
                // retry until we either get a match or we reach the end.
                if (result == MatchResult::NotMatched) {
                    pathpos++;
                // Only return MatchResult::Matched if there are no more
                // patterns left, because the next match could be a wildcard
                // matching an empty character sequence.
                } else if (result == MatchResult::EndOfInput &&
                           patpos >= this->patlen) {
                    *pattern_pos = patpos;
                    *path_pos = pathpos;
                    return MatchResult::Matched;
                } else {
                    break;
                }
            }
            continue;
        }

        MatchResult result = this->match_fixed(&patpos, &pathpos);
        if (result == MatchResult::GotSlash) {
            if (this->pattern[patpos++] == '/') {
                last_slash = patpos;
                pathpos++;
            } else {
                return MatchResult::NotMatched;
            }
        }  else if (result == MatchResult::EndOfInput) {
            return MatchResult::NotMatched;
        } else if (result == MatchResult::NotMatched) {
            return MatchResult::NotMatched;
        }
    }

    if (pathpos >= this->pathlen) {
        *pattern_pos = patpos;
        *path_pos = pathpos;
        return MatchResult::Matched;
    }

    return MatchResult::NotMatched;
}

/*
 * Strip one path component from the current this->path and return the new
 * offset. For example given "foo/bar/blah" and an offset of 0 will return a
 * new offset 4, so a substr(4) on the path will result in "bar/blah".
 */
std::optional<size_t> GlobPath::skip_component(const size_t &pathpos)
{
    std::string_view pathpart = this->path.substr(pathpos);

    const size_t &pos = pathpart.find_first_of('/');
    if (pos != std::string_view::npos)
        return pathpos + pos + 1;

    return std::nullopt;
}

bool GlobPath::match(void)
{
    // First of all, look whether the pattern contains a slash, because if it
    // does we only want to match the basename.
    bool slash_found = false;
    for (size_t i = 0; i < this->patlen; ++i) {
        if (this->pattern[i] == '/') {
            slash_found = true;
            break;
        }
    }

    // If no slash is found, we need to strip all of the directory parts.
    if (!slash_found) {
        const size_t pos = this->path.find_last_of('/');
        if (pos != std::string_view::npos) {
            this->path.remove_prefix(pos + 1);
            this->pathlen -= pos + 1;
        }
    }

    size_t patpos = 0;
    size_t pathpos = 0;

    bool is_recursive = false;

    for (;;) {
        MatchResult result = this->match_norec(&patpos, &pathpos);

        // We got a full match, so we can return early even if is_recursive is
        // true.
        if (result == MatchResult::Matched)
            return true;

        if (is_recursive) {
            // Another recursive pattern found, so we need to treat it as a
            // successful match but repeat the cycle nonetheless.
            if (result == MatchResult::GotRecursive)
                continue;

            // Retry the recursive match by skipping the next path component
            // until we got none left (which means that the match has failed).
            std::optional<size_t> newpos = this->skip_component(pathpos);
            if (newpos)
                pathpos = *newpos;
            else
                return false;

            continue;
        }

        // This sets is_recursive, which will work differently than
        // non-recursive matches in that it will retry if we got
        // MatchResult::NotMatched from match_norec until there are no path
        // components left.
        if (result == MatchResult::GotRecursive) {
            is_recursive = true;
            continue;
        }

        return false;
    }
}

bool globpath(const std::string &pattern, const std::string &path)
{
    return GlobPath(pattern, path).match();
}
