#!/usr/bin/env python
"""
  Copyright (c) 2019 Trail of Bits, Inc.
 
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
 
      http://www.apache.org/licenses/LICENSE-2.0
 
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
"""
from binaryninja import *
from os import listdir
from sys import argv

if len(argv) < 2:
    print("please specify the location of the memory directory in the workspace as an argument for this program")
    print("Example: `python locate_traces.py ./ws/memory/`")
    exit(1)


memory_directory_path = argv[1]
traces = []

def mark_traces_in_mapping(mapping):
    path = memory_directory_path
    if path[-1] != "/":
        path += "/"

    bv = binaryview.BinaryViewType["ELF"].open(path + mapping)
    if(not bv):
        return
    print(path + mapping)
    bv.update_analysis_and_wait()
    base = int(mapping.split("_")[0], 16)
    for func in bv.functions:
        for bb in func:
            if bb.start < base:
                traces.append(base + bb.start)
            else:
                traces.append(bb.start)

def is_executable(mapping):
    umask = "".join(mapping.split("_")[2:4])
    return "x" in umask

def mark_all_traces():
    for mapping in listdir(memory_directory_path):
        if is_executable(mapping):
            mark_traces_in_mapping(mapping)

def write_all_traces_to_file():
    with open("trace_list","a+") as trace_file:
        trace_file.write("======TRACE=ADDRESSES======\n")
        for trace in traces:
            trace_file.write(hex(trace).strip("L") + '\n')


if __name__  == "__main__":
    mark_all_traces()
    write_all_traces_to_file()
