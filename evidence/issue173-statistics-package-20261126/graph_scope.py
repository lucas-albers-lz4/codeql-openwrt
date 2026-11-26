from collections import defaultdict
import re

P = "[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*"
PVAR = "[A-Za-z0-9_.+@-]+"
V = "CONFIG_" + PVAR
C = r"\$\(" + V + r"\)"
COND = rf"(?:{C}|\$\(and {C}(?:,{C})+\))+"
B = re.compile(rf"^\$\(curdir\)/({P})/compile$")
I = re.compile(rf"^\$\(if ({COND}),(.*)\)$")
NAME = re.compile(rf"^(package|prereq)-(?:\$\((CONFIG_PACKAGE_{PVAR})\))? \+= ({P})$")
DIRECT = re.compile(
    rf"^\$\(curdir\)/({P})/(compile|variants|default-variant) (\+=|:=) (.+)$"
)
BUILD = re.compile(rf"^buildtypes-({P}) = (host)$")


def split(text, delimiter=" "):
    depth = 0
    previous = 0
    tokens = []
    for i, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == delimiter and depth == 0:
            tokens.append(text[previous:i])
            previous = i + 1
        if depth < 0:
            raise ValueError("unbalanced graph expression: " + text)
    if depth != 0:
        raise ValueError("unbalanced graph expression: " + text)
    return tokens + [text[previous:]]


def checked_path(path):
    if any(part in (".", "..") for part in path.split("/")):
        raise ValueError("graph path alias: " + path)
    return path


def dependencies(token):
    if m := B.fullmatch(token):
        return [checked_path(m[1])]
    m = I.fullmatch(token)
    if not m:
        raise ValueError("unknown graph dependency: " + token)
    branches = split(m[2], ",")
    if len(branches) not in (1, 2):
        raise ValueError("unknown graph branches: " + token)
    if not branches[0] and len(branches) != 2:
        raise ValueError("empty graph branch")
    if not all(not x or B.fullmatch(x) or I.fullmatch(x) for x in branches):
        raise ValueError("unknown graph branch: " + token)
    return [target for branch in branches if branch for target in dependencies(branch)]


def parse(lines):
    depend = defaultdict(list)
    directives = defaultdict(list)
    other = []
    prereq = []
    for line in lines:
        if not line:
            continue
        if m := NAME.fullmatch(line):
            directives[checked_path(m[3])].append(line)
            if m[1] == "prereq":
                prereq.append(line)
        elif m := BUILD.fullmatch(line):
            directives[checked_path(m[1])].append(line)
        elif m := DIRECT.fullmatch(line):
            target, kind, op, rhs = m.groups()
            checked_path(target)
            if (kind == "default-variant") != (op == ":="):
                raise ValueError("unknown graph operator: " + line)
            if kind == "compile":
                depend[target].append(
                    (line, [x for term in split(rhs) for x in dependencies(term)])
                )
            else:
                expr = rf"\$\(if {C},{PVAR}\)" if kind == "variants" else PVAR
                if not re.fullmatch(expr, rhs):
                    raise ValueError("unknown graph declaration: " + line)
                directives[target].append(line)
        else:
            other.append(line)
    return depend, directives, prereq, other


SCOPE_SHA = "4d8e05cff63f11484fdacdc7b0c0adfedd3340dbedcb7bef6929b0e982cfd7f9"


def scope(raw, config, roots=("feeds/luci/luci-app-statistics", "kernel/linux")):
    if not raw.endswith(b"\n") or any(byte < 32 and byte != 10 for byte in raw):
        raise ValueError("graph must use ASCII LF lines")
    lines = raw.decode("ascii").split("\n")[:-1]
    depend, directives, prereq, other = parse(lines)
    if other:
        raise ValueError("unknown graph directive: " + other[0])
    if not roots or len(set(roots)) != len(roots):
        raise ValueError("graph roots must be nonempty and unique")
    for root in roots:
        if not isinstance(root, str) or not re.fullmatch(P, root):
            raise ValueError("invalid graph root")
        checked_path(root)
    seen = set(roots)
    work = list(seen)
    while work:
        for _, children in depend.get(work.pop(), []):
            for child in children:
                if child not in seen:
                    seen.add(child)
                    work.append(child)
    aliases = {target for target in seen if target in directives}
    aliases |= {
        target.rsplit("/", 1)[0]
        for target in seen
        if "/" in target
        and target.rsplit("/", 1)[0] in directives
        and any(
            line.startswith("buildtypes-")
            and target.rsplit("/", 1)[1] in line.split(" = ", 1)[1].split()
            for line in directives[target.rsplit("/", 1)[0]]
        )
    }
    selected = {
        line.split("=", 1)[0]
        for line in config.decode("ascii").splitlines()
        if line.endswith(("=y", "=m"))
    }
    wanted = {line for target in seen for line, _ in depend.get(target, [])}
    wanted |= {line for target in aliases for line in directives[target]} | set(prereq)
    wanted |= {
        line
        for line in lines
        if (match := NAME.fullmatch(line))
        and match[1] == "package"
        and (match[2] is None or match[2] in selected)
    }
    rows = [line for line in lines if line in wanted]
    return ("\n".join(rows) + "\n").encode("ascii")
