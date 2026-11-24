/** Unfiltered relation facts for isolated fixture observation; no membership filter. */
import javascript

/** Emit the class name of a literal operand without conflating source/value strings. */
string literalType(Literal literal) {
  literal instanceof NumberLiteral and result = "NumberLiteral"
  or literal instanceof BigIntLiteral and result = "BigIntLiteral"
  or literal instanceof StringLiteral and result = "StringLiteral"
  or literal instanceof BooleanLiteral and result = "BooleanLiteral"
  or literal instanceof NullLiteral and result = "NullLiteral"
  or literal instanceof RegExpLiteral and result = "RegExpLiteral"
}

predicate fact(PropAccess access, Expr related, string relation, string value) {
  related = access.getBase() and relation = "base-raw-class" and value = related.getAPrimaryQlClass()
  or
  related = access.getBase().stripParens() and relation = "base-stripped-class" and value = related.getAPrimaryQlClass()
  or
  related = access.getBase() and related instanceof VarAccess and relation = "base-raw-name" and value = related.(VarAccess).getName()
  or
  related = access.getBase().stripParens() and related instanceof VarAccess and relation = "base-stripped-name" and value = related.(VarAccess).getName()
  or
  related = access.getPropertyNameExpr() and relation = "property-raw-class" and value = related.getAPrimaryQlClass()
  or
  related = access.getPropertyNameExpr().stripParens() and relation = "property-stripped-class" and value = related.getAPrimaryQlClass()
  or
  related = access.(DotExpr).getProperty() and relation = "dot-name-decoded" and value = related.(Identifier).getName()
  or
  related = access.(IndexExpr).getIndex() and related instanceof Literal and relation = "index-literal-raw" and value = related.(Literal).getRawValue()
  or
  related = access.(IndexExpr).getIndex() and related instanceof Literal and relation = "index-literal-value" and value = related.(Literal).getValue()
  or
  related = access.(IndexExpr).getIndex().stripParens() and related instanceof Literal and relation = "index-stripped-literal-type" and value = literalType(related.(Literal))
  or
  related = access.(IndexExpr).getIndex().stripParens() and related instanceof Literal and relation = "index-stripped-literal-raw" and value = related.(Literal).getRawValue()
  or
  related = access.(IndexExpr).getIndex().stripParens() and related instanceof Literal and relation = "index-stripped-literal-value" and value = related.(Literal).getValue()
  or
  related = access.(IndexExpr).getIndex().stripParens().(UnaryExpr) and relation = "unary-operator" and value = related.(UnaryExpr).getOperator()
  or
  related = access.(IndexExpr).getIndex().stripParens().(UnaryExpr).getOperand() and relation = "unary-operand-class" and value = related.getAPrimaryQlClass()
  or
  related = access.(IndexExpr).getIndex().stripParens().(UnaryExpr).getOperand() and related instanceof Literal and relation = "unary-operand-literal-type" and value = literalType(related.(Literal))
  or
  related = access.(IndexExpr).getIndex().stripParens().(UnaryExpr).getOperand() and related instanceof Literal and relation = "unary-operand-literal-raw" and value = related.(Literal).getRawValue()
  or
  related = access.(IndexExpr).getIndex().stripParens().(UnaryExpr).getOperand() and related instanceof Literal and relation = "unary-operand-literal-value" and value = related.(Literal).getValue()
  or
  related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral) and relation = "template-string-observation" and value = related.toString()
  or
  related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral) and relation = "template-semantic-string" and value = related.getStringValue()
  or
  related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral) and relation = "template-child-count" and value = related.(TemplateLiteral).getNumElement().toString()
  or
  exists(int i |
    related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral).getElement(i) and
    relation = "template-child-index" and value = i.toString()
  )
  or
  related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral).getAnElement() and
  relation = "template-child-class" and value = related.getAPrimaryQlClass()
  or
  related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral).getAnElement().(TemplateElement) and
  relation = "template-cooked" and value = related.(TemplateElement).getValue()
  or
  related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral).getAnElement().(TemplateElement) and
  relation = "template-has-cooked-value" and
  (if related.(TemplateElement).hasValue() then value = "true" else value = "false")
  or
  related = access.(IndexExpr).getIndex().stripParens().(TemplateLiteral).getAnElement().(TemplateElement) and
  relation = "template-raw" and value = related.(TemplateElement).getRawValue()
  or
  exists(CallExpr call |
    call.getCallee().stripParens() = access and related = call and
    relation = "call-callee" and
    (if call instanceof OptionalUse then value = "optional" else value = "nonoptional")
  )
  or
  related = access and relation = "property-optionality" and
  (if access instanceof OptionalUse then value = "optional" else value = "nonoptional")
}

from PropAccess access, Expr related, string relation, string value
where fact(access, related, relation, value)
select access, related, access.getFile().getAbsolutePath(),
  access.getLocation().getStartLine().toString(), access.getLocation().getStartColumn().toString(),
  access.getLocation().getEndLine().toString(), access.getLocation().getEndColumn().toString(), relation, value
