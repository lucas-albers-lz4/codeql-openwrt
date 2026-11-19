import javascript
from AddExpr e, string kind, string endpoint
where
  exists(PropAccess p, PropAccess env |
    e.getLeftOperand().stripParens() = p and p.getPropertyName() = "cgi_base" and
    p.getBase().stripParens() = env and env.getPropertyName() = "env" and
    env.getBase().stripParens().(VarAccess).getName() = "L"
  ) and
  endpoint = e.getRightOperand().stripParens().(StringLiteral).getValue() and
  endpoint.regexpMatch("/cgi-[A-Za-z0-9_-]+") and kind = "base-plus-string"
select e.getFile().getAbsolutePath(), e.getLocation().getStartLine().toString(),
  e.getLocation().getStartColumn().toString(), e.getLocation().getEndLine().toString(),
  e.getLocation().getEndColumn().toString(), kind, endpoint, "candidate"
