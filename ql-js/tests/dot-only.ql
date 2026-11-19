import javascript
from DotExpr access
where access.getBase().stripParens().(VarAccess).getName() = "rpc" and
  access.getPropertyName() = "declare" and access.getFile().getRelativePath().matches("%.js")
select access.getFile().getAbsolutePath(), access.getLocation().getStartLine().toString(),
  access.getLocation().getStartColumn().toString(), access.getLocation().getEndLine().toString(),
  access.getLocation().getEndColumn().toString(), "dot", "candidate"
