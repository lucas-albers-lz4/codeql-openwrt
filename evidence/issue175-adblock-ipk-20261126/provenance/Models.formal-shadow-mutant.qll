/**
 * Bounded M3/M4 models over generated TreeSitter nodes.
 * Same-file calls, named `popen` from `'fs'`, builtin `system()`,
 * syntactic local taint, and enclosing rpcd method names.
 */

import codeql.files.FileSystem
import codeql.ucode.ast.internal.TreeSitter
import codeql.ucode.Diagnostics
import codeql.ucode.internal.SourceDeclaredFs

/** Gets the text of a string literal (joined fragments). */
string stringLiteralValue(UCODE::String s) {
  result = strictconcat(int i, UCODE::StringFragment frag |
      frag = s.getChild(i)
    |
      frag.getValue() order by i
    )
}

/** An `import { name } from 'module'` specifier. */
predicate namedImport(UCODE::ImportStatement imp, string moduleName, string localName) {
  moduleName = stringLiteralValue(imp.getSource()) and
  exists(UCODE::ImportSpecifier spec |
    spec = imp.getClause().getNamed().getChild(_) and
    localName = spec.getName().(UCODE::Identifier).getValue() and
    not exists(spec.getAlias())
  )
}

/** Holds if an import binds `localName` in the current module scope. */
predicate importedLocalName(UCODE::ImportStatement imp, string localName) {
  exists(UCODE::ImportSpecifier spec |
    spec = imp.getClause().getNamed().getChild(_) and
    (
      exists(UCODE::Identifier alias |
        alias = spec.getAlias() and localName = alias.getValue()
      )
      or
      not exists(spec.getAlias()) and
      localName = spec.getName().(UCODE::Identifier).getValue()
    )
  )
  or
  exists(UCODE::Identifier defaultImport |
    defaultImport = imp.getClause().getDefault() and
    localName = defaultImport.getValue()
  )
  or
  localName = imp.getClause().getNamespace().getChild().getValue()
}

/** Direct identifier callee of a call; member and wrapped callees are not resolved. */
UCODE::Identifier calleeIdent(UCODE::CallExpression c) {
  result = c.getFunction().(UCODE::Identifier)
}

/** A call whose callee is the identifier `name`. */
class NamedCall extends UCODE::CallExpression {
  string name;

  NamedCall() { name = calleeIdent(this).getValue() }

  string getName() { result = name }

  UCODE::AstNode getArgument(int i) { result = this.getArguments().getChild(i) }
}

/** `popen(...)` where `popen` is imported from `'fs'` in the same file. */
class NamedFsPopenCall extends NamedCall {
  NamedFsPopenCall() {
    this.getName() = "popen" and
    sourceDeclaredFsCall(this, "popen")
  }
}

/**
 * Direct, unaliased source-declared `fs.stat` with one non-spread expression.
 * This is conservative source attribution, not a resolved runtime callable.
 * Unsupported and nonmatching calls remain inconclusive.
 */
class SourceDeclaredFsStatCall extends NamedCall {
  SourceDeclaredFsStatCall() {
    sourceDeclaredFsCall(this, "stat") and
    this.getArgument(0) instanceof UCODE::Expression and
    not exists(int i | i != 0 and exists(this.getArgument(i)))
  }

  /** The raw syntax node for the sole path argument. */
  UCODE::AstNode getPathArgument() { result = this.getArgument(0) }
}

/**
 * Direct, unaliased source-declared `fs.rename` with exactly two non-spread
 * expression arguments. This is source attribution, not runtime resolution.
 * Unsupported and nonmatching calls remain inconclusive.
 */
class SourceDeclaredFsRenameCall extends NamedCall {
  SourceDeclaredFsRenameCall() {
    sourceDeclaredFsCall(this, "rename") and
    this.getArgument(0) instanceof UCODE::Expression and
    this.getArgument(1) instanceof UCODE::Expression and
    not exists(int i | i != 0 and i != 1 and exists(this.getArgument(i)))
  }

  /** The raw first argument node, observed as the source path. */
  UCODE::AstNode getSourceArgument() { result = this.getArgument(0) }

  /** The raw second argument node, observed as the destination path. */
  UCODE::AstNode getDestinationArgument() { result = this.getArgument(1) }
}

/**
 * Direct, unaliased source-declared `fs.open` with literal `wx` mode and
 * two or three non-spread expression arguments. This is source syntax, not
 * runtime binding or proof of an opened handle. Nonmatches are inconclusive.
 */
class SourceDeclaredFsOpenWxCall extends NamedCall {
  SourceDeclaredFsOpenWxCall() {
    sourceDeclaredFsCall(this, "open") and
    this.getArgument(0) instanceof UCODE::Expression and
    exists(UCODE::String mode |
      mode = this.getArgument(1) and
      mode.getChild(0).(UCODE::StringFragment).getValue() = "wx" and
      not exists(mode.getChild(1))
    ) and
    (not exists(this.getArgument(2)) or this.getArgument(2) instanceof UCODE::Expression) and
    not exists(int i | i != 0 and i != 1 and i != 2 and exists(this.getArgument(i)))
  }

  /** The raw path argument at index 0. */
  UCODE::AstNode getPathArgument() { result = this.getArgument(0) }

  /** The raw literal mode argument at index 1. */
  UCODE::AstNode getModeArgument() { result = this.getArgument(1) }

  /** The optional raw permission expression at index 2. */
  UCODE::AstNode getPermissionArgument() { result = this.getArgument(2) }
}

/** Identifier or rest identifier from a formal parameter list. */
private predicate systemFormal(UCODE::FormalParameters ps, UCODE::Identifier id) {
  id = ps.getChild(_)
  or
  exists(UCODE::RestElement rest | rest = ps.getChild(_) and id = rest.getChild())
}

/** A named formal visible in a function body, including nested closures. */
private predicate systemFormalInBody(UCODE::AstNode occurrence) {
  exists(UCODE::Identifier id, UCODE::AstNode body |
    id.getValue() = "system" and
    (
      exists(UCODE::FunctionDeclaration f |
        systemFormal(f.getParameters(), id) and body = f.getBody()
      )
      or
      exists(UCODE::FunctionExpression f |
        systemFormal(f.getParameters(), id) and body = f.getBody()
      )
      or
      exists(UCODE::ArrowFunction f |
        (id = f.getParameter() or systemFormal(f.getParameters(), id)) and body = f.getBody()
      )
    ) and
    occurrence.getParent*() = body
  )
}

/** The nearest lexical boundary containing a declaration. Switch cases share a body scope. */
private predicate systemLexicalScope(UCODE::AstNode scope) {
  scope instanceof UCODE::StatementBlock or
  scope instanceof UCODE::StatementList or
  scope instanceof UCODE::SwitchBody or
  scope instanceof UCODE::ForStatement or
  scope instanceof UCODE::ForAltStatement or
  scope instanceof UCODE::ForInStatement or
  scope instanceof UCODE::ForInAltStatement or
  scope instanceof UCODE::Program
}

private UCODE::AstNode systemDeclarationScope(UCODE::AstNode declaration) {
  result = declaration.getParent+() and
  systemLexicalScope(result) and
  not exists(UCODE::AstNode inner |
    inner = declaration.getParent+() and inner.getParent+() = result and
    systemLexicalScope(inner)
  )
}

/** Source order used for declarations; ucode compiles lexical names in order. */
private predicate systemDeclaredBefore(UCODE::Identifier name, UCODE::AstNode occurrence) {
  name.getLocation().getFile() = occurrence.getLocation().getFile() and
  (
    name.getLocation().getStartLine() < occurrence.getLocation().getStartLine()
    or
    name.getLocation().getStartLine() = occurrence.getLocation().getStartLine() and
    name.getLocation().getStartColumn() < occurrence.getLocation().getStartColumn()
  )
}

/** A named function declaration in an enclosing lexical scope. */
private predicate systemFunctionInScope(UCODE::AstNode occurrence) {
  exists(UCODE::FunctionDeclaration f |
    f.getName().getValue() = "system" and
    systemDeclaredBefore(f.getName(), occurrence) and
    occurrence.getParent*() = systemDeclarationScope(f)
  )
  or
  exists(UCODE::FunctionExpression f |
    f.getName().getValue() = "system" and occurrence.getParent*() = f.getBody()
  )
}

/** A lexical declarator in an enclosing block, or its for-loop scope. */
private predicate systemVariableInScope(UCODE::AstNode occurrence) {
  exists(UCODE::VariableDeclarator d, UCODE::AstNode scope |
    d.getName().getValue() = "system" and
    systemDeclaredBefore(d.getName(), occurrence) and
    (
      exists(UCODE::ForStatement f | d.getParent() = f.getInitializer() and scope = f)
      or
      exists(UCODE::ForAltStatement f | d.getParent() = f.getInitializer() and scope = f)
      or
      not exists(UCODE::ForStatement f | d.getParent() = f.getInitializer()) and
      not exists(UCODE::ForAltStatement f | d.getParent() = f.getInitializer()) and
      scope = systemDeclarationScope(d)
    ) and
    occurrence.getParent*() = scope
  )
  or
  exists(UCODE::ForInStatement f, UCODE::Identifier id |
    exists(f.getKind()) and
    (id = f.getVariable() or id = f.getKey() or id = f.getValue()) and
    id.getValue() = "system" and occurrence.getParent*() = f
  )
  or
  exists(UCODE::ForInAltStatement f, UCODE::Identifier id |
    exists(f.getKind()) and
    (id = f.getVariable() or id = f.getKey() or id = f.getValue()) and
    id.getValue() = "system" and occurrence.getParent*() = f
  )
  or
  exists(UCODE::CatchClause c |
    c.getParameter().getValue() = "system" and occurrence.getParent*() = c.getBody()
  )
}

/**
 * Direct `system(...)` treated as the builtin when no supported lexical or
 * imported binding is visible. This is a syntactic approximation, not proof
 * of runtime target: globals may be reassigned, and an excluded local or
 * imported binding may itself refer to the builtin. Exclusion is not safety.
 */
class BuiltinSystemCall extends NamedCall {
  BuiltinSystemCall() {
    this.getName() = "system" and
    not systemFunctionInScope(this) and
    not systemVariableInScope(this) and
    not exists(UCODE::ImportStatement imp |
      imp.getLocation().getFile() = this.getLocation().getFile() and
      importedLocalName(imp, "system")
    )
  }
}

/** Same-file `function name(...) { ... }`. */
UCODE::FunctionDeclaration functionDecl(string name) {
  result.getName().getValue() = name
}

/**
 * A deliberately narrow same-file helper association, not a runtime resolver.
 * A complete top-level declaration must precede the direct non-optional call.
 * Every same-name token in the file must be this declaration's name or a
 * direct call callee. Even unrelated or later shadows, writes, and escapes
 * make the target unknown. Parse-error files are excluded.
 */
predicate sameFileCall(NamedCall c, UCODE::FunctionDeclaration def) {
  def = functionDecl(c.getName()) and
  c.getLocation().getFile() = def.getLocation().getFile() and
  def.getParent() instanceof UCODE::Program and
  not exists(c.getOptionalChain()) and
  (def.getLocation().getEndLine() < c.getLocation().getStartLine() or
    def.getLocation().getEndLine() = c.getLocation().getStartLine() and
    def.getLocation().getEndColumn() < c.getLocation().getStartColumn()) and
  not exists(UCODE::Identifier id |
    id.getLocation().getFile() = c.getLocation().getFile() and
    id.getValue() = c.getName() and
    id != def.getName() and
    not id = calleeIdent(any(NamedCall call))
  ) and
  not exists(UCODE::ShorthandPropertyIdentifier id |
    id.getLocation().getFile() = c.getLocation().getFile() and
    id.getValue() = c.getName()
  ) and
  not exists(ExtractionError error | error.getLocation().getFile() = c.getLocation().getFile())
}

/** `callPackageVersionCheck('netifd')` (literal package name). */
class CallPackageVersionCheckNetifd extends NamedCall {
  CallPackageVersionCheckNetifd() {
    this.getName() = "callPackageVersionCheck" and
    stringLiteralValue(this.getArgument(0).(UCODE::String)) = "netifd"
  }
}

/** Property identifier token value. */
string propertyName(UCODE::AstNode n) {
  result = n.(UCODE::PropertyIdentifier).getValue()
  or
  result = n.(UCODE::Identifier).getValue()
}

/** `name: { call: function(...) { ... } }` method body. */
UCODE::FunctionExpression rpcCallFn(string name) {
  exists(UCODE::Pair method, UCODE::Pair callPair, UCODE::Object body |
    name = propertyName(method.getKey()) and
    body = method.getValue() and
    callPair = body.getChild(_) and
    propertyName(callPair.getKey()) = "call" and
    result = callPair.getValue()
  )
}

/** `getFeatures: { call: function(...) { ... } }`. */
UCODE::FunctionExpression getFeaturesCallFn() { result = rpcCallFn("getFeatures") }

/** Holds if `n` is inside the `getFeatures.call` function. */
predicate inGetFeaturesCall(UCODE::AstNode n) { n.getParent*() = getFeaturesCallFn() }

/** Enclosing rpcd method name for a node inside `methods.<name>.call`. */
string rpcMethodName(UCODE::AstNode n) {
  exists(string name, UCODE::FunctionExpression fn |
    fn = rpcCallFn(name) and
    n.getParent*() = fn and
    result = name
  )
}

/** `shellquote(...)` wrapping `n` (complete-argument quoting, not a global sanitizer). */
predicate wrappedByShellquote(UCODE::AstNode n) {
  exists(NamedCall sq |
    sq.getName() = "shellquote" and
    n.getParent*() = sq.getArgument(0)
  )
}

/** `request.args` or `request.args.<k>`. */
class RequestArgsAccess extends UCODE::MemberExpression {
  RequestArgsAccess() {
    exists(UCODE::MemberExpression inner |
      this.getObject() = inner and
      inner.getObject().(UCODE::Identifier).getValue() = "request" and
      inner.getProperty().getValue() = "args"
    )
    or
    this.getObject().(UCODE::Identifier).getValue() = "request" and
    this.getProperty().getValue() = "args"
  }
}

/** Syntactic local taint: node is a request.args access or a tree containing one. */
predicate locallyTainted(UCODE::AstNode n) {
  n instanceof RequestArgsAccess
  or
  locallyTainted(n.getAFieldOrChild())
}

/** Two nodes sit in the same rpcd `methods.<name>.call` body (one function node). */
predicate sameRpcMethod(UCODE::AstNode a, UCODE::AstNode b) {
  exists(UCODE::FunctionExpression fn | fn = rpcCallFn(_) and a.getParent*() = fn and b.getParent*() = fn)
}

/**
 * Same-function name binding from a tainted initializer or assignment.
 * Not CFG/SSA: later reassignment in the same method is not distinguished.
 */
predicate taintedBinding(RequestArgsAccess source, string name) {
  exists(UCODE::VariableDeclarator d |
    source.getParent*() = d.getValue() and
    name = d.getName().getValue() and
    sameRpcMethod(source, d)
  )
  or
  exists(UCODE::AssignmentExpression a |
    source.getParent*() = a.getRight() and
    name = a.getLeft().(UCODE::Identifier).getValue() and
    sameRpcMethod(source, a)
  )
  or
  exists(UCODE::VariableDeclarator d, UCODE::Identifier inner |
    inner.getParent*() = d.getValue() and
    taintedBinding(source, inner.getValue()) and
    name = d.getName().getValue() and
    sameRpcMethod(source, d)
  )
  or
  exists(UCODE::AssignmentExpression a, UCODE::Identifier inner |
    inner.getParent*() = a.getRight() and
    taintedBinding(source, inner.getValue()) and
    name = a.getLeft().(UCODE::Identifier).getValue() and
    sameRpcMethod(source, a)
  )
}

/** Positive control: a sink argument is locally tainted, including same-function bindings. */
predicate taintReachesSink(UCODE::AstNode source, NamedCall sink) {
  source instanceof RequestArgsAccess and
  exists(UCODE::AstNode arg | arg = sink.getArgument(_) |
    source.getParent*() = arg
    or
    exists(UCODE::Identifier use |
      use.getParent*() = arg and
      sameRpcMethod(source, use) and
      taintedBinding(source, use.getValue())
    )
  )
}

/** Direct child index of `child` in template `tmpl`. */
int templateChildIndex(UCODE::TemplateString tmpl, UCODE::AstNode child) { child = tmpl.getChild(result) }

/**
 * Conservative absence-of-shadowing check, not proof of trusted semantics.
 * Every same-file occurrence of the identifier must be a direct callee. Imports, declarations, parameters, assignments and
 * aliases all make the binding unknown, even in an unrelated lexical scope.
 * This deliberately does not infer the behavior of locally defined helpers.
 */
predicate unambiguousShellquoteCall(NamedCall sq) {
  sq.getName() = "shellquote" and
  not exists(UCODE::Identifier id |
    id.getLocation().getFile() = sq.getLocation().getFile() and
    id.getValue() = "shellquote" and
    not id = calleeIdent(any(NamedCall c))
  )
}

/**
 * Bounded command grammar: only a fixed non-interpreter command followed by
 * literal, unquoted words and whitespace. Unknown commands, shell separators,
 * substitutions, assignments, wrappers and interpreter programs stay candidates.
 * Extend this allowlist only with command semantics and regression controls.
 */
predicate supportedQuotedArgumentPrefix(UCODE::StringFragment prefix) {
  prefix.getValue().regexpMatch("[ \\t]*(swconfig|echo|printf)[ \\t]+([A-Za-z0-9_./-]+[ \\t]+)*")
}

/**
 * Necessary shape for a future barrier: an unchanged call in the first
 * substitution of a supported literal command. Both adjacent fragments must
 * establish shell-word boundaries. The template must end at that substitution's
 * trailing fragment; a later substitution is unquoted program text, so a shape
 * match there would not describe a completely quoted argument. Quoting or
 * backslashes in other template text remain unsupported, as do local helpers or
 * ambiguous shellquote bindings.
 */
predicate supportedShellquoteTemplateShape(RequestArgsAccess src, NamedCall sink) {
  taintReachesSink(src, sink) and
  exists(
    NamedCall sq, UCODE::TemplateSubstitution sub, UCODE::TemplateString tmpl,
    UCODE::StringFragment prefix, UCODE::StringFragment suffix
  |
    unambiguousShellquoteCall(sq) and
    src.getParent*() = sq.getArgument(0) and
    sq = sub.getChild() and
    prefix = tmpl.getChild(0) and
    sub = tmpl.getChild(1) and
    suffix = tmpl.getChild(2) and
    not exists(tmpl.getChild(3)) and
    tmpl = sink.getArgument(_) and
    supportedQuotedArgumentPrefix(prefix) and
    suffix.getValue().regexpMatch("[ \\t].*") and
    not exists(UCODE::StringFragment frag |
      frag = tmpl.getChild(_) and frag.getValue().regexpMatch(".*[\"\\\\].*")
    )
  )
}

/**
 * No shellquote implementation currently has a trusted semantic model. Spelling
 * and absence of local declarations do not prove a builtin exists or quotes
 * safely. Retain candidates until binding and helper semantics are established.
 * Keep the shape check independently testable for that future model.
 */
predicate completeQuotedTemplateArg(RequestArgsAccess src, NamedCall sink) {
  supportedShellquoteTemplateShape(src, sink) and
  none()
}

/** The whole sink argument is `shellquote(tainted)` — executable/command selection. */
predicate quotedEntireCommand(RequestArgsAccess src, NamedCall sink) {
  taintReachesSink(src, sink) and
  exists(NamedCall sq |
    sq.getName() = "shellquote" and
    src.getParent*() = sq.getArgument(0) and
    sq = sink.getArgument(_)
  )
}

/** Shell-injection candidate: taint reaches the sink and is not a complete quoted argument. */
predicate shellInjectionCandidate(RequestArgsAccess src, NamedCall sink) {
  taintReachesSink(src, sink) and
  not completeQuotedTemplateArg(src, sink)
}

/** `export function init_action` in installed luci.sys (`sys.uc`). */
UCODE::FunctionDeclaration initActionFn() {
  result = functionDecl("init_action") and
  result.getLocation().getFile().getRelativePath() = "usr/share/ucode/luci/sys.uc" and
  result = any(UCODE::ExportStatement e).getDeclaration()
}

/** Holds if `n` is inside `init_action` in `sys.uc`. */
predicate inInitAction(UCODE::AstNode n) { n.getParent*() = initActionFn() }

/** `export function process_list` in installed luci.sys (`sys.uc`). */
UCODE::FunctionDeclaration processListFn() {
  result = functionDecl("process_list") and
  result.getLocation().getFile().getRelativePath() = "usr/share/ucode/luci/sys.uc" and
  result = any(UCODE::ExportStatement e).getDeclaration()
}

/** Holds if `n` is inside `process_list` in `sys.uc`. */
predicate inProcessList(UCODE::AstNode n) { n.getParent*() = processListFn() }

/** `export function conntrack_list` in installed luci.sys (`sys.uc`). */
UCODE::FunctionDeclaration conntrackListFn() {
  result = functionDecl("conntrack_list") and
  result.getLocation().getFile().getRelativePath() = "usr/share/ucode/luci/sys.uc" and
  result = any(UCODE::ExportStatement e).getDeclaration()
}

/** Holds if `n` is inside `conntrack_list` in `sys.uc`. */
predicate inConntrackList(UCODE::AstNode n) { n.getParent*() = conntrackListFn() }

/** `setInitAction: { call: function(...) { ... } }`. */
UCODE::FunctionExpression setInitActionCallFn() {
  exists(UCODE::Pair method, UCODE::Pair callPair, UCODE::Object body |
    propertyName(method.getKey()) = "setInitAction" and
    body = method.getValue() and
    callPair = body.getChild(_) and
    propertyName(callPair.getKey()) = "call" and
    result = callPair.getValue()
  )
}

/** Holds if `n` is inside the `setInitAction.call` function. */
predicate inSetInitActionCall(UCODE::AstNode n) { n.getParent*() = setInitActionCallFn() }
