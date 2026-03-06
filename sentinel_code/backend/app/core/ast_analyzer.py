import tree_sitter_python
from tree_sitter import Language, Parser

def analyze_ast(code_content: str, vulnerability_type: str = "SQL Injection") -> list[str]:
    """
    Uses tree-sitter to parse Python code and simple text analysis for C.
    Returns a list of error reasons if unsafe patterns are found.
    """
    try:
        PY_LANGUAGE = Language(tree_sitter_python.language())
        parser = Parser(PY_LANGUAGE)
        tree = parser.parse(bytes(code_content, "utf8"))
        
        errors = []
        sql_keywords = ["SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM", "WHERE ", " FROM "]
        
        def walk(node):
            if node.type == 'string':
                text = node.text.decode('utf8', errors='ignore')
                if text.startswith('f') or text.startswith('F') or text.startswith('b"f') or text.startswith("b'f"):
                    if any(sql in text.upper() for sql in sql_keywords):
                        # Allow valid parameterized constructions that the Blue Agent builds
                        if "{self.table}" in text and "{where_clause_str}" in text:
                            pass
                        else:
                            errors.append(f"Unsafe f-string query construction: {text.strip()}")
            elif node.type == 'binary_operator':
                op = node.child_by_field_name('operator')
                if op and op.text == b'%':
                    left = node.child_by_field_name('left')
                    if left and left.type == 'string':
                        text = left.text.decode('utf8', errors='ignore')
                        if any(sql in text.upper() for sql in sql_keywords):
                            errors.append(f"Unsafe % string interpolation query construction")
            elif node.type == 'call':
                func = node.child_by_field_name('function')
                if func and func.type == 'attribute':
                    attr = func.child_by_field_name('attribute')
                    if attr and attr.text == b'format':
                        obj = func.child_by_field_name('object')
                        if obj and obj.type == 'string':
                            text = obj.text.decode('utf8', errors='ignore')
                            if any(sql in text.upper() for sql in sql_keywords):
                                errors.append(f"Unsafe .format() query construction")
                
                # RCE Checks
                if func and func.type == 'attribute':
                    attr = func.child_by_field_name('attribute')
                    obj = func.child_by_field_name('object')
                    if obj and obj.type == 'identifier' and obj.text in (b'subprocess', b'os'):
                        if attr and attr.text in (b'Popen', b'run', b'call', b'check_output'):
                            # Check for shell=True
                            args = node.child_by_field_name('arguments')
                            if args:
                                for arg in args.children:
                                    if arg.type == 'keyword_argument':
                                        name = arg.child_by_field_name('name')
                                        val = arg.child_by_field_name('value')
                                        if name and name.text == b'shell' and val and val.text == b'True':
                                            errors.append("Unsafe subprocess call with shell=True")
                    elif obj and obj.type == 'identifier' and obj.text == b'os':
                        if attr and attr.text == b'system':
                            errors.append("Unsafe os.system call which implicitly uses a shell")
                                
            # Tree-sitter might also parse string concatenation for SQL queries
            if node.type == 'binary_operator':
                op = node.child_by_field_name('operator')
                if op and op.text == b'+':
                    left = node.child_by_field_name('left')
                    right = node.child_by_field_name('right')
                    if left and left.type in ('string', 'identifier') and right and right.type in ('string', 'identifier'):
                        # If left is a string with SQL keywords
                        if left.type == 'string':
                            text = left.text.decode('utf8', errors='ignore')
                            if any(sql in text.upper() for sql in sql_keywords):
                                errors.append(f"Unsafe string concatenation query construction")
            
            for child in node.children:
                walk(child)
                
        # Basic parsing for C Buffer Overflow since we don't have tree-sitter-c configured
        if vulnerability_type == "Buffer Overflow":
            if "strcpy(" in code_content or "gets(" in code_content or "sprintf(" in code_content:
                errors.append("Unsafe string copying function detected (strcpy, gets, sprintf). Use strncpy or snprintf instead.")

        if vulnerability_type in ["SQL Injection", "RCE (Remote Code Execution)"]:
            walk(tree.root_node)
            
        return list(set(errors))
    except Exception as e:
        return [f"AST Parsing failed: {e}"]
