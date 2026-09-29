"""Shared prompt helpers used by all backend prompt modules."""

try:
    from ..config import LANGUAGE
except ImportError:
    from config import LANGUAGE

# CodeQL RAG collection holding this language's standard-library docs
# (populated by scripts/codeql_docs_fetcher.py).
STDLIB_COLLECTION = f"codeql_{LANGUAGE}_stdlib"

# The dataflow-library import line shown in inline example query snippets.
DATAFLOW_IMPORT = {
    "java": "import semmle.code.java.dataflow.DataFlow",
    "python": "import semmle.code.python.dataflow.new.DataFlow",
    "javascript": "import semmle.javascript.dataflow.DataFlow",
}.get(LANGUAGE, "import semmle.code.java.dataflow.DataFlow")

# Human-readable language name used in prompt text (e.g. "Python files").
LANGUAGE_LABEL = {"java": "Java", "python": "Python", "javascript": "JavaScript"}.get(
    LANGUAGE, LANGUAGE.capitalize()
)


def source_sink_taint_examples() -> str:
    """Return the standard source/sink/sanitizer/taint-step example blocks."""
    if LANGUAGE == "python":
        return _source_sink_taint_examples_python()
    return _source_sink_taint_examples_java()


def _source_sink_taint_examples_python() -> str:
    return """#### Sources (Input/Entry Points):
Identify points where untrusted data enters the system:
- User input parameters
- External data sources
- Network/file inputs
- Function parameters accepting external data

#### Source Examples
package: flask
class: Request
method: get (via request.args/request.form)
signature: request.args.get(name)

package: os
class: (module-level)
method: environ.get
signature: os.environ.get(key)

package: builtins
class: (module-level)
method: input
signature: input(prompt=None)

package: urllib.parse
class: (module-level)
method: urlparse
signature: urlparse(url)

package: json
class: (module-level)
method: loads
signature: json.loads(s)

#### Sinks (Dangerous Operations):
Identify operations that became dangerous when given malicious input:
- File operations that could be exploited
- Database operations
- System calls
- Any operation the fix made safer

#### Sink Examples
package: subprocess
class: (module-level)
method: run / check_output / Popen
signature: subprocess.run(args, shell=False)

package: os
class: (module-level)
method: system
signature: os.system(command)

package: builtins
class: (module-level)
method: open
signature: open(file, mode='r')

package: yaml
class: (module-level)
method: load / full_load
signature: yaml.load(stream, Loader=...)

package: pickle
class: (module-level)
method: loads / load
signature: pickle.loads(data)

#### Sanitizers (Security Controls):
Identify validation/sanitization based on the diff:
- What validation existed in REMOVED (-) lines? This was INSUFFICIENT
- What validation was ADDED (+) in the fix? This is the PROPER sanitization
- Your CodeQL query should only treat the ADDED validation as a sanitizer
- Do NOT treat removed/insufficient validation as a sanitizer

#### Additional Taint Steps:
Identify data transformations that preserve taint:
- Variable assignments
- Function calls that propagate data
- Object construction with tainted data
- String manipulations (f-strings, .format(), concatenation)

#### Additional Taint Step Examples
package: os.path
class: (module-level)
method: join
signature: os.path.join(path, *paths)

package: pathlib
class: Path
method: __truediv__ / joinpath
signature: Path(path) / other

package: builtins
class: str
method: format
signature: str.format(*args, **kwargs)"""


def _source_sink_taint_examples_java() -> str:
    return """#### Sources (Input/Entry Points):
Identify points where untrusted data enters the system:
- User input parameters
- External data sources
- Network/file inputs
- Method parameters accepting external data

#### Source Examples
package: javax.servlet.http
class: HttpServletRequest
method: getParameter
signature: String getParameter(String name)

package: java.util.zip
class: ZipEntry
method: getName
signature: String getName()

package: org.jboss.resteasy.spi
class: HttpRequest
method: getDecodedFormParameters
signature: MultivaluedMap<String,String> getDecodedFormParameters()

package: java.io
class: ByteArrayInputStream
method: ByteArrayInputStream
signature: ByteArrayInputStream(byte[] buf)

package: javax.mail.internet
class: MimeMessage
method: getAllHeaders
signature: Enumeration<Header> getAllHeaders()

#### Sinks (Dangerous Operations):
Identify operations that became dangerous when given malicious input:
- File operations that could be exploited
- Database operations
- System calls
- Any operation the fix made safer

#### Sink Examples
package: java.sql
class: Statement
method: execute
signature: boolean execute(String sql)

package: java.io
class: FileInputStream
method: FileInputStream
signature: FileInputStream(File file)

package: java.lang
class: Runtime
method: exec
signature: Process exec(String[] cmdarray)

package: org.apache.wicket.core.request.handler
class: IPartialPageRequestHandler
method: appendJavaScript
signature: void appendJavaScript(CharSequence seq)

package: org.thymeleaf
class: TemplateEngine
method: process
signature: void process(String template, IContext context, Writer writer)

#### Sanitizers (Security Controls):
Identify validation/sanitization based on the diff:
- What validation existed in REMOVED (-) lines? This was INSUFFICIENT
- What validation was ADDED (+) in the fix? This is the PROPER sanitization
- Your CodeQL query should only treat the ADDED validation as a sanitizer
- Do NOT treat removed/insufficient validation as a sanitizer

#### Additional Taint Steps:
Identify data transformations that preserve taint:
- Variable assignments
- Method calls that propagate data
- Object construction with tainted data
- String manipulations

#### Additional Taint Step Examples
package: java.lang
class: StringBuilder
method: append
signature: StringBuilder append(String str)

package: java.net
class: URL
method: URL
signature: URL(String url)

package: java.io
class: File
method: File
signature: File(String path)

package: java.net
class: URL
method: URL
signature: URL(String spec)

package: org.json
class: JSONObject
method: toString
signature: String toString()"""


def query_skeleton() -> str:
    """Return the standard CodeQL query template skeleton."""
    if LANGUAGE == "python":
        return _query_skeleton_python()
    return _query_skeleton_java()


def _query_skeleton_python() -> str:
    return """```ql
/**
 * @name [Vulnerability Name based on analysis]
 * @description [Description derived from the vulnerability pattern]
 * @problem.severity error
 * @security-severity [score based on severity]
 * @precision high
 * @tags security
 * @kind path-problem
 * @id [unique-id]
 */
import python
import semmle.code.python.dataflow.new.DataFlow
import semmle.code.python.dataflow.new.TaintTracking
import semmle.code.python.dataflow.new.RemoteFlowSources

class Source extends DataFlow::Node {
  Source() {
    exists([AST node type from analysis] |
      /* Fill based on AST patterns for sources identified in Phase 1 & 2 */
      and this.asExpr() = [appropriate mapping]
    )
  }
}

class Sink extends DataFlow::Node {
  Sink() {
    exists([AST node type] |
      /* Fill based on AST patterns for sinks */
      and this.asExpr() = [appropriate mapping]
    ) or
    exists([Alternative AST pattern] |
      /* Additional sink patterns from analysis */
      and [appropriate condition]
    )
  }
}

class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    exists([AST node type for sanitizers] |
      /* Fill based on sanitizer patterns from Phase 1 & 2 */
    )
  }
}

module MyPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof Source
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof Sink
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer instanceof Sanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    /* Fill based on additional taint steps from analysis */
  }
}

module MyPathFlow = TaintTracking::Global<MyPathConfig>;
import MyPathFlow::PathGraph

from
  MyPathFlow::PathNode source,
  MyPathFlow::PathNode sink
where
  MyPathFlow::flowPath(source, sink)
select
  sink.getNode(),
  source,
  sink,
  "[Alert message based on vulnerability]",
  source.getNode(),
  "[source description]"
```"""


def _query_skeleton_java() -> str:
    return """```ql
/**
 * @name [Vulnerability Name based on analysis]
 * @description [Description derived from the vulnerability pattern]
 * @problem.severity error
 * @security-severity [score based on severity]
 * @precision high
 * @tags security
 * @kind path-problem
 * @id [unique-id]
 */
import java
import semmle.code.java.frameworks.Networking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.dataflow.ExternalFlow

class Source extends DataFlow::Node {
  Source() {
    exists([AST node type from analysis] |
      /* Fill based on AST patterns for sources identified in Phase 1 & 2 */
      and this.asExpr() = [appropriate mapping]
    )
  }
}

class Sink extends DataFlow::Node {
  Sink() {
    exists([AST node type] |
      /* Fill based on AST patterns for sinks */
      and this.asExpr() = [appropriate mapping]
    ) or
    exists([Alternative AST pattern] |
      /* Additional sink patterns from analysis */
      and [appropriate condition]
    )
  }
}

class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    exists([AST node type for sanitizers] |
      /* Fill based on sanitizer patterns from Phase 1 & 2 */
    )
  }
}

module MyPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof Source
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof Sink
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer instanceof Sanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    /* Fill based on additional taint steps from analysis */
  }
}

module MyPathFlow = TaintTracking::Global<MyPathConfig>;
import MyPathFlow::PathGraph

from
  MyPathFlow::PathNode source,
  MyPathFlow::PathNode sink
where
  MyPathFlow::flowPath(source, sink)
select
  sink.getNode(),
  source,
  sink,
  "[Alert message based on vulnerability]",
  source.getNode(),
  "[source description]"
```"""

def phase1_expected_output() -> str:
    return f"""### Expected Output Format
Please provide the analysis in this structured format:

```
## Vulnerability Research Summary
[Summary of findings from Chroma database research about this vulnerability type]

## CVE Information (if available)
[Summary of information from NIST CVE database]

## Relevant Files
[List ONLY the {LANGUAGE_LABEL} files that are directly related to the vulnerability including test files.]
- [filename] - [Brief description of why this file is relevant]
- [filename2] - [Brief description of why this file is relevant]

## Sources
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Sinks
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Sanitizers
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Additional Taint Steps
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Vulnerability Summary
[Brief description of the vulnerability pattern and how the fix addresses it]
```"""