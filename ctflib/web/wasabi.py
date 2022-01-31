# This is probably a terrible idea
analysis = """
num_loads = 0;
Wasabi.analysis.load = function (location, op, memarg, value) {
  if (filter_functions.length === 0 || filter_functions.includes(location.func)) {
    if (debug) console.log("load", {location, op, memarg, value})
    num_loads += 1;
  }
};

num_stores = 0;
Wasabi.analysis.store = function (location, op, memarg, value) {
  if (filter_functions.length === 0 || filter_functions.includes(location.func)) {
    if (debug) console.log("store", {location, op, memarg, value})
    num_stores += 1;
  }
};


num_calls = 0;
Wasabi.analysis.call_pre = function (location, targetFunc, args, indirectTableIdx) {
  if (filter_functions.length === 0 || filter_functions.includes(location.func)) {
    if (debug) console.log("call", {location, targetFunc, args, indirectTableIdx})
    num_calls += 1;
  }
};

num_inst = 0;
Wasabi.analysis.binary = function (location, op, first, second, result) {
  if (filter_functions.length === 0 || filter_functions.includes(location.func)) {
    if (debug) console.log("bin", {location, op, first, second, result})
    num_inst += 1;
  }
};
Wasabi.analysis.unary = function (location, op, input, result) {
  if (filter_functions.length === 0 || filter_functions.includes(location.func)) {
    if (debug) console.log("unary", {location, op, input, result})
    num_inst += 1;
  }
};

filter_functions = [0]
debug = false;


function send_input(input) {
  num_calls = num_inst = num_loads = num_stores = 0;
  // Probably need to change this
  f = document.getElementById("flag");
  b = document.getElementById("button");
  f.value = input;
  b.click();
}

function get_param() {
  return num_inst;
}

function run_attack() {
  prepend = true;
  pad = "a";
  flag = ""
  // Warmup
  send_input(Math.random().toString())
  rounds = debug ? 1 : 100;
  for (j = 0; j < rounds; j++) {
    dist = new Map();
    for (i = 19; i < 128; i++) {
      send_input(pad + (prepend ? String.fromCharCode(i) + flag : flag + String.fromCharCode(i)))
      param = get_param();
      if (dist.has(param)) {
        dist.get(param).push(String.fromCharCode(i));
      } else {
        dist.set(param, [String.fromCharCode(i)]);
      }
    }
    sel = []
    curr_min = Number.MAX_SAFE_INTEGER;
    k = 0;
    dist.forEach((val, key, map) => {
      if (val.length < curr_min) {
        sel = val;
        curr_min = val.length;
        k = key;
      }
    })
    if (debug) console.log(dist)
    if (sel.length === 0) {
      console.log("flag (died)", flag)
      return;
    }
    const confidence = 1 / (sel.length) - (sel.length / 109);
    flag = prepend ? sel[0] + flag : flag + sel[0];
    console.log({flag, options: sel, confidence, k});
    if (confidence < 0) {
      break;
    }
  }
}

function find_length() {
  // Warmup
  send_input(Math.random().toString())
  dist = new Map();
  for (i = 1; i < 128; i++) {
    send_input("a".repeat(i))
    param = get_param();
    if (dist.has(param)) {
      dist.get(param).push(i);
    } else {
      dist.set(param, [i]);
    }
  }
  sel = []
  curr_min = Number.MAX_SAFE_INTEGER;
  k = 0;
  dist.forEach((val, key, map) => {
    if (val.length < curr_min) {
      sel = val;
      curr_min = val.length;
      k = key;
    }
  })
  console.log(dist)
}
"""

import os

def find_file(ext: str):
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.endswith("."+ext):
                return os.path.join(root, file)

def init_wasabi():
    html = find_file("html")
    wasm = find_file("wasm")
    wasm_name = wasm[2:-5]
    if html is None:
        raise Exception("HTML file not found")
    if wasm is None:
        raise Exception("WASM file not found")
    print(f"Found html: {html}")
    print(f"Found wasm: {wasm}")
    os.system(f"wasabi {wasm}")
    include_script = f"<script src=\"out/{wasm_name}.wasabi.js\"></script>\n"
    include_script += f"<script src=\"analysis.js\"></script>"
    open("./analysis.js", "w").write(analysis)
    os.system(f"mv {wasm} {wasm}.old")
    os.system(f"mv out/{wasm} {wasm}")
    with open(html, "r") as f:
        html_content = f.read()
    os.system(f"mv {html} {html}.old")
    with open(html, "w") as f:
        f.write(html_content.replace("<head>", "<head>"+include_script))
    print("Done")
    print("Run `python3 -m http.server &` to serve the files")
