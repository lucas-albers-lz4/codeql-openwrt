/** Test-only omission mutant: dot accesses only. */
import javascript
from DotExpr access, string kind, string property
where
  access.getBase().stripParens().(VarAccess).getName() = "fs" and
  kind = "dot" and property = access.getPropertyName() and
  access.getFile().getRelativePath().matches("%.js")
select access.getFile().getAbsolutePath(), access.getLocation().getStartLine().toString(),
  access.getLocation().getStartColumn().toString(), access.getLocation().getEndLine().toString(),
  access.getLocation().getEndColumn().toString(), kind, property, "candidate"
