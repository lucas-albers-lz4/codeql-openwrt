/**
 * UCI syntax candidates only. Computed keys outside the bounded literal syntax
 * below remain unknown; this does not resolve bindings or establish calls.
 * The first selected entity is a database-local PropAccess identity.
 * Fixture compilation and result comparison remain required before use.
 */
import javascript

string receiverForm(PropAccess a) {
  a.getBase().stripParens().(VarAccess).getName() = "uci" and result = "bare"

}

string memberKind(PropAccess a) {
  a instanceof DotExpr and result = "dot"
  or
  a instanceof IndexExpr and result = "computed-index"
}

/** Exact, deliberately bounded property-key conversion for literal syntax. */
string decimalNumber(NumberLiteral n) {
  n.getRawValue().regexpMatch("0|[1-9][0-9]{0,8}") and result = n.getRawValue()
}

string computedName(Expr input) {
  exists(StringLiteral literal, string raw |
    literal = input.stripParens() and raw = literal.getRawValue() and
    (raw.regexpMatch("'[A-Za-z0-9_$#<>. -]{0,128}'") or
     raw.regexpMatch("\"[A-Za-z0-9_$#<>. -]{0,128}\"")) and
    result = literal.getValue()
  )
  or
  exists(TemplateLiteral template |
    template = input.stripParens() and template.getNumElement() = 0 and result = ""
  )
  or
  exists(TemplateLiteral template, TemplateElement element |
    template = input.stripParens() and template.getNumElement() = 1 and
    element = template.getElement(0) and element.hasValue() and
    element.getRawValue().regexpMatch("[A-Za-z0-9_$#<>. -]{1,128}") and
    result = element.getValue()
  )
  or
  result = decimalNumber(input.stripParens().(NumberLiteral))
  or
  exists(UnaryExpr unary, string value |
    unary = input.stripParens() and
    value = decimalNumber(unary.getOperand().(NumberLiteral)) and
    (unary.getOperator() = "+" and result = value or
     unary.getOperator() = "-" and
       (value = "0" and result = "0" or value != "0" and result = "-" + value))
  )
  or
  exists(Literal literal |
    literal = input.stripParens() and
    (literal instanceof BooleanLiteral or literal instanceof NullLiteral) and
    literal.getRawValue() = ["true", "false", "null"] and result = literal.getRawValue()
  )
  or
  exists(BigIntLiteral literal, string raw |
    literal = input.stripParens() and raw = literal.getRawValue() and
    raw.regexpMatch("(0|[1-9][0-9]{0,127})n") and
    result = raw.regexpCapture("(0|[1-9][0-9]{0,127})n", 1)
  )
}

string knownName(PropAccess a) {
  a instanceof DotExpr and result = a.getPropertyName() and not result.matches("#%")
  or
  result = computedName(a.(IndexExpr).getIndex())
}

string knownness(PropAccess a) {
  exists(knownName(a)) and result = "true"
  or
  not exists(knownName(a)) and result = "false"
}

string property(PropAccess a) {
  result = knownName(a)
  or
  not exists(knownName(a)) and result = "<unknown>"
}

from PropAccess access, string receiver, string kind, string known, string name
where
  not access instanceof OptionalUse and
  (access instanceof IndexExpr or exists(knownName(access))) and
  receiver = receiverForm(access) and kind = memberKind(access) and
  known = knownness(access) and name = property(access) and
  access.getFile().getRelativePath().matches("%.js")
select access, access.getFile().getAbsolutePath(),
  access.getLocation().getStartLine().toString(), access.getLocation().getStartColumn().toString(),
  access.getLocation().getEndLine().toString(), access.getLocation().getEndColumn().toString(),
  receiver, kind, known, name, "candidate"
