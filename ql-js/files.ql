import javascript
from TopLevel t
where t.getFile().getRelativePath().matches("%.js")
select t.getFile().getAbsolutePath()
