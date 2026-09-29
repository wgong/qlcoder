import python

from Function f
where
  exists(f.getLocation().getFile().getRelativePath()) and
  f.getName() != ""
select
  f.getName() as name,
  f.getLocation().getFile().getRelativePath() as file,
  f.getLocation().getStartLine() as start_line,
  f.getLocation().getEndLine() as end_line
