// SPDX-License-Identifier: LGPL-3.0-only
#include "globpath.hh"

#include <optional>

enum class MatchResult {
    Matched,
    NotMatched,
    EndOfInput,
    Invalid,
    GotSlash,
};

class GlobPath {
    std::string_view pattern;
    std::string_view path;
    const size_t patlen;
    size_t pathlen;
    size_t patpos;
    size_t pathpos;

    MatchResult match_cclass(size_t*, const char&);
    MatchResult match_fixed(void);

    public:
        GlobPath(const std::string&, const std::string&);
        bool match(void);
};

GlobPath::GlobPath(const std::string &needle, const std::string &haystack)
    : pattern(needle)
    , path(haystack)
    , patlen(needle.size())
    , pathlen(haystack.size())
    , patpos(0)
    , pathpos(0)
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
        if (pattern[nextpat] == '\\') {
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

MatchResult GlobPath::match_fixed(void)
{
    size_t ppos = this->patpos;
    size_t cpos = this->pathpos;

    while (ppos < this->patlen) {
        const char &p = this->pattern[ppos];

        if (p == '*') {
            this->patpos = ppos;
            this->pathpos = cpos;
            return MatchResult::Matched;
        } else if (cpos >= this->pathlen) {
            return MatchResult::EndOfInput;
        } else if (this->path[cpos] == '/') {
            // Handle escaped forward slash.
            if (this->pattern[ppos] == '\\' && ppos + 1 < this->patlen) {
                if (this->pattern[ppos + 1] == '/')
                    ppos++;
            }
            this->patpos = ppos;
            this->pathpos = cpos;
            return MatchResult::GotSlash;
        } else if (p == '[') {
            MatchResult result = this->match_cclass(&ppos, this->path[cpos]);
            if (result == MatchResult::NotMatched)
                return MatchResult::NotMatched;
        } else if (p != '?') {
            if (p == '\\') {
                if (++ppos >= this->patlen)
                    return MatchResult::NotMatched;
            }
            if (this->pattern[ppos] != this->path[cpos])
                return MatchResult::NotMatched;
        }

        ppos++;
        cpos++;
    }

    this->patpos = ppos;
    this->pathpos = cpos;
    return this->pathpos >= this->pathlen
         ? MatchResult::Matched
         : MatchResult::NotMatched;
}

bool GlobPath::match(void)
{
    // First of all, look whether the pattern contains a slash, because if it
    // does we only want to match the basename.
    bool slash_found = false;
    for (size_t i = 0; i < this->patlen; ++i) {
        // Skip character classes using a dummy path character ('x').
        if (this->pattern[i] == '[')
            this->match_cclass(&i, 'x');
        else if (this->pattern[i] == '/') {
            slash_found = true;
            break;
        }
    }

    // If no slash is found, we need to strip the directory parts.
    if (!slash_found) {
        const size_t pos = this->path.find_last_of('/');
        if (pos != std::string_view::npos) {
            this->path.remove_prefix(pos + 1);
            this->pathlen -= pos + 1;
        }
    }

    while (this->patpos < this->patlen) {
        if (this->pattern[this->patpos] == '*') {
            // Eat up all consecutive "any string" wildcard characters.
            while (this->pattern[this->patpos] == '*') {
                // If the wildcard is the last character in pattern, anything
                // from the rest of path will match.
                if (this->patpos >= this->patlen)
                    return true;
                else
                    this->patpos++;
            }
            for (;;) {
                MatchResult result = this->match_fixed();
                // If the fixed match fails, we need to skip one character and
                // retry until we either get a match or we reach the end.
                if (result == MatchResult::NotMatched)
                    this->pathpos++;
                // Only return true if there are no more patterns left, because
                // the next match could be a wildcard matching an empty
                // character sequence.
                else if (result == MatchResult::EndOfInput &&
                         this->patpos >= this->patlen)
                    return true;
                else
                    break;
            }
            continue;
        }

        MatchResult result = this->match_fixed();
        if (result == MatchResult::GotSlash) {
            if (this->pattern[this->patpos++] == '/')
                this->pathpos++;
            else
                return false;
        }  else if (result == MatchResult::EndOfInput) {
            return false;
        } else if (result == MatchResult::NotMatched) {
            return false;
        }
    }

    return this->pathpos >= this->pathlen;
}

bool globpath(const std::string &pattern, const std::string &path)
{
    return GlobPath(pattern, path).match();
}
