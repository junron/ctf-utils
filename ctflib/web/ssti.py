import html


def get_popen(string):
	string = preprocess_string(string)
	s = "<class 'subprocess.Popen'>"
	if s not in string:
		return None
	i = string.index(s)
	s = string[:i]
	return s.count(",")
def get_builtinimporter(string):
	string = preprocess_string(string)
	s = "<class '_frozen_importlib.BuiltinImporter'>"
	if s not in string:
		return None
	i = string.index(s)
	s = string[:i]
	return s.count(",")
def get_fileloader(string):
	string = preprocess_string(string)
	s = "<class '_frozen_importlib_external.FileLoader'>"
	if s not in string:
		return None
	i = string.index(s)
	s = string[:i]
	return s.count(",")

def preprocess_string(string: str):
	string = html.unescape(string)
	# For good measure!
	string = html.unescape(string)
	string = html.unescape(string)
	start = "[<class"
	# Don't really care about the end cos it's indexed from the front
	if start not in string:
		return string
	i = string.index(start)
	return string[i:]
