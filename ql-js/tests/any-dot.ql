import javascript
string accessKind(PropAccess a) {
  a instanceof DotExpr and result = "dot"
  or
  a instanceof IndexExpr and a.getPropertyName() = "declare" and result = "literal-index"
  or
  a instanceof IndexExpr and not exists(a.getPropertyName()) and result = "computed-index"
}
from PropAccess access, string kind
where access.getBase().stripParens().(VarAccess).getName() = "rpc" and
  kind = accessKind(access) and access.getFile().getRelativePath().matches("%.js")
select access.getFile().getAbsolutePath(), access.getLocation().getStartLine().toString(),
  access.getLocation().getStartColumn().toString(), access.getLocation().getEndLine().toString(),
  access.getLocation().getEndColumn().toString(), kind, "candidate"
