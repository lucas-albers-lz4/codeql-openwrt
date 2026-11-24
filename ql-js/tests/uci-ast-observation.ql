/** Unfiltered fixture observation; does not assert inventory membership. */
import javascript

string optionality(PropAccess access) {
  access instanceof OptionalUse and result = "optional"
  or
  not access instanceof OptionalUse and result = "nonoptional"
}

string memberKind(PropAccess access) {
  access instanceof DotExpr and result = "dot"
  or
  access instanceof IndexExpr and result = "computed-index"
}

from PropAccess access, string optional, string kind
where
  optional = optionality(access) and kind = memberKind(access)
select access, access.getBase(), access.getBase().stripParens(), access.getFile().getAbsolutePath(),
  access.getLocation().getStartLine().toString(), access.getLocation().getStartColumn().toString(),
  access.getLocation().getEndLine().toString(), access.getLocation().getEndColumn().toString(),
  kind, optional
