import python

from Class c
where
  exists(c.getLocation().getFile().getRelativePath()) and
  c.getName() != ""
select
  c.getName() as name,
  c.getLocation().getFile().getRelativePath() as file,
  c.getLocation().getStartLine() as start_line,
  c.getLocation().getEndLine() as end_line
