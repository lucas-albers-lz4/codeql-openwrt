/** Syntactic fs property accesses, not resolved runtime targets. */
import javascript

string accessKind(PropAccess a) {
  a instanceof DotExpr and result = "dot"
  or
  a instanceof IndexExpr and exists(a.getPropertyName()) and result = "literal-index"
  or
  a instanceof IndexExpr and not exists(a.getPropertyName()) and result = "computed-index"
}

string propertyName(PropAccess a) {
  result = a.getPropertyName()
  or
  not exists(a.getPropertyName()) and result = "<unknown>"
}

from PropAccess access, string kind, string property
where
  access.getBase().stripParens().(VarAccess).getName() = "fs" and
  kind = accessKind(access) and property = propertyName(access) and
  access.getFile().getRelativePath().matches("%.js")
select access.getFile().getAbsolutePath(), access.getLocation().getStartLine().toString(),
  access.getLocation().getStartColumn().toString(), access.getLocation().getEndLine().toString(),
  access.getLocation().getEndColumn().toString(), kind, property, "candidate"
