# Python jail escape


## `ShellCandidates` class
This class contains 2 members, `popen` and `importer`, two ways of gaining a shell in python.


## `get_subclasses` function
Returns python code, which when executed will return all classes currently loaded. May need to be wrapped in `print`


## `find_class` function
Usage: `find_class(output, class)`  
Output is the output when the output of `get_subclasses()` is run. `class` is `ShellCandidates.importer` or ``ShellCandidates.popen`  
Returns an array of (index, classname).

## `system` function
Usage: `system(index, command)`
This function currently only supports the importer method of running commands.
Example:
```python
if __name__ == '__main__':
    subc = repr(eval(get_subclasses()))
    n = find_class(subc, ShellCandidates.importer)[0][0]
    eval(system(n, "ls"))
```
