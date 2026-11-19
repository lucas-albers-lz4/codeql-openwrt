import javascript
predicate envBase(Expr e) {
  exists(PropAccess p, PropAccess env |
    e.stripParens() = p and p.getPropertyName() = "cgi_base" and
    p.getBase().stripParens() = env and env.getPropertyName() = "env" and
    env.getBase().stripParens().(VarAccess).getName() = "L"
  )
}
predicate construction(Expr e, string kind, string endpoint) {
  exists(AddExpr add |
    e = add and envBase(add.getLeftOperand()) and
    endpoint = add.getRightOperand().stripParens().(StringLiteral).getValue() and
    kind = "base-plus-string"
  ) or
  exists(TemplateLiteral t |
    e = t and envBase(t.getAnElement()) and
    endpoint = t.getAnElement().(TemplateElement).getValue() and
    kind = "template-base-and-suffix"
  )
}
from Expr e, string kind, string endpoint
where construction(e, kind, endpoint) and endpoint.regexpMatch("/cgi-[A-Za-z0-9_-]*")
select e.getFile().getAbsolutePath(), e.getLocation().getStartLine().toString(),
  e.getLocation().getStartColumn().toString(), e.getLocation().getEndLine().toString(),
  e.getLocation().getEndColumn().toString(), kind, endpoint, "candidate"
