/**
 * @name Issue 175 direct system coordinate witness
 * @description Test-only direct call positions, including shadowed calls.
 * @kind problem
 * @problem.severity recommendation
 * @id ucode/testing/issue175-coordinate-witness
 * @tags testing
 */
import codeql.ucode.m3.Models
from NamedCall c
where c.getName() = "system"
select c,
  "builtin system() in " + c.getLocation().getFile().getBaseName() + " at line " +
    c.getLocation().getStartLine().toString()
