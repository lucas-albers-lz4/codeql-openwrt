import javascript
import semmle.javascript.Errors
from JSParseError e
select e.getTopLevel().getFile().getRelativePath(), e.getMessage(), e.getLine()
