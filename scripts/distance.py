#!/usr/bin/env python3

import argparse
import collections
import functools
import networkx as nx
import re

class memoize:
  # From https://github.com/S2E/s2e-env/blob/master/s2e_env/utils/memoize.py

  def __init__(self, func):
    self._func = func
    self._cache = {}

  def __call__(self, *args):
    if not isinstance(args, collections.abc.Hashable):
      return self._func(args)

    if args in self._cache:
      return self._cache[args]

    value = self._func(*args)
    self._cache[args] = value
    return value

  def __repr__(self):
    # Return the function's docstring
    return self._func.__doc__

  def __get__(self, obj, objtype):
    # Support instance methods
    return functools.partial(self.__call__, obj)

unreachable_weight = 10

#################################
# Get graph node name
#################################
def node_name (name):
  if is_cg:
    return "{fun: %s\\}" % name
  else:
    return "\"{%s}" % name

#################################
# Find the graph node for a name
#################################
@memoize
def find_nodes (name, is_cg):
  n_name = node_name (name)
  result=[]
  if is_cg:
    for n, d in G.nodes(data=True):
      ret = re.search(r"{fun: .*\\}", d.get('label', ''))
      if ret:
        if n_name == ret.group():
          # print(n_name)
          # print(ret.group())
          result.append(n)

    return result
  else: 
    return [n for n, d in G.nodes(data=True) if n_name in d.get('label', '')]

##################################
# Calculate Distance
##################################
def distance (name, bb_index):
  distance = -1
  shortest_without_incall = -1
  contain_incall = False
  icall_site = ""
  call_site = ""
  
  for n in find_nodes (name, is_cg):

    if is_cg:
      for t in targets:
        try:
          shortest, path = nx.single_source_dijkstra(G, n, t)
          caller=re.findall(r"{fun: (.*)\\}", G.nodes[path[shortest-1]]['label'])[0]
          callee=re.findall(r"{fun: (.*)\\}", G.nodes[path[shortest]]['label'])[0]
          if distance > shortest or distance == -1:
            distance = shortest
            shortest_without_incall = shortest
            for i in range(shortest):
              if G.edges[path[i], path[i+1]]['color'] == "red" :
                shortest_without_incall = i
                caller=re.findall(r"{fun: (.*)\\}", G.nodes[path[i]]['label'])[0]
                callee=re.findall(r"{fun: (.*)\\}", G.nodes[path[i+1]]['label'])[0]
                break
            #print("from %s to %s; distance is %f"%(n,t,shortest))
            #print("%s to %s, distance is %d"%(name, callee, distance))

        except nx.NetworkXNoPath:
          pass
    else:
      for t_name, bb_d in bb_distance.items():
        for t in find_nodes(t_name, is_cg):
          try:
            shortest = nx.dijkstra_path_length(G, n, t)
            if distance > 10 * bb_d + shortest + 1 or distance == -1 :
              distance = 10 * bb_d + shortest + 1
              if t_name in incalls:
                shortest_without_incall = 10 * bb_distance_without_incall[t_name] + shortest + 1
                contain_incall = True
                icall_site = t_name
                call_site = t_name
              else:
                contain_incall = False
                call_site = t_name
          except nx.NetworkXNoPath:
            pass

  if distance != -1:
    if is_cg:
      out.write (name)
      out.write (":")
      out.write (caller)
      out.write (":")
      out.write (callee)
      out.write (",")
      out.write (str(distance))
      out.write (",")
      out.write (str(shortest_without_incall))
      out.write ("\n")
    else :
      #print("%s to %s, distance is %d"%(name, call_site, distance))
      if G.predecessors(n) is not None:
        for pred in G.predecessors(n):
          pred_name = re.findall(r"{(.*)}", G.nodes[pred]['label'])[0]
          n_name = re.findall(r"{(.*)}", G.nodes[n]['label'])[0]
          if pred_name in f_out_index.keys():
            for exit_index in f_out_index[pred_name]:
              pre_loc = exit_index
              cur_loc = bb_index[n_name]
              # print("%s to %s, distance is %d"%(func_call[pred_name], name, distance))
              edge_index = (pre_loc >> 1) ^ cur_loc
              out.write(str(edge_index))           
              out.write (",")
              if not contain_incall:
                out.write (str(distance))
              else:
                out.write (str(shortest_without_incall))
                icallout.write (str(edge_index))
                icallout.write (",")
                icalledge = (bb_index[icall_site] >> 1) ^ (f_index[icall_site])
                icallout.write (str(icalledge))
                icallout.write ("\n")
              out.write ("\n")
          else:
            if pred_name not in bb_index.keys():
              continue
            pre_loc = bb_index[pred_name]
            cur_loc = bb_index[n_name]
            # print("%s to %s, distance is %d"%(pred_name, name, distance))
            edge_index = (pre_loc >> 1) ^ cur_loc
            out.write(str(edge_index))           
            out.write (",")
            if not contain_incall:
              out.write (str(distance))
            else :
              out.write (str(shortest_without_incall))
              icallout.write (str(edge_index))
              icallout.write (",")
              icalledge = (bb_index[icall_site] >> 1) ^ (f_index[icall_site])
              icallout.write (str(icalledge))
              icallout.write ("\n")
            out.write ("\n")
            if name in f_index.keys() and shortest != 0:
              # print("%s to %s, distance is %d"%(name, func_call[name], distance))
              pre_loc = bb_index[name]
              cur_loc = f_index[n_name]
              edge_index = (pre_loc >> 1) ^ cur_loc
              out.write(str(edge_index))           
              out.write (",")
              if not contain_incall:
                out.write (str(distance))
              else:
                out.write (str(shortest_without_incall))
                icallout.write (str(edge_index))
                icallout.write (",")
                icalledge = (bb_index[icall_site] >> 1) ^ (f_index[icall_site])
                icallout.write (str(icalledge))
                icallout.write ("\n")
              out.write ("\n")

      if shortest == 0 and bb_d != 0:
        pre_loc = bb_index[name]
        try:
          cur_loc = f_index[name]
          if cur_loc is not None:
            distance = 10 * bb_d + shortest
            edge_index = (pre_loc >> 1) ^ cur_loc
            out.write(str(edge_index))           
            out.write (",")
            out.write (str(distance))
            out.write ("\n")
        except KeyError:
          pass


##################################
# Main function
##################################
if __name__ == '__main__':
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-d', '--dot', type=str, required=True, help="Path to dot-file representing the graph.")
  parser.add_argument ('-t', '--targets', type=str, required=True, help="Path to file specifying Target nodes.")
  parser.add_argument ('-o', '--out', type=str, required=True, help="Path to output file containing distance for each node.")
  parser.add_argument ('-n', '--names', type=str, required=True, help="Path to file containing name for each node.")
  parser.add_argument ('-c', '--cg_distance', type=str, help="Path to file containing call graph distance.")
  parser.add_argument ('-s', '--cg_callsites', type=str, help="Path to file containing mapping between basic blocks and called functions.")
  parser.add_argument ('-is', '--cg_incallsites', type=str, help="Path to file containing mapping between basic blocks and indirect called functions.")
  parser.add_argument ('-fi', '--f_index', type=str, help="Path to file containing the function entry index.")
  parser.add_argument ('-foi', '--f_out_index', type=str, help="Path to file containing the function out index.")
  parser.add_argument ('-bbi', '--bb_index', type=str, help="Path to file containing the basic block index.")
  parser.add_argument ('-z', '--bb_icall', type=str, help="Path to file containing the nearest incall edge basic block have.")

  args = parser.parse_args ()

  print ("\nParsing %s .." % args.dot)
  G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(args.dot))
  # print (nx.info(G))

  is_cg = "Call Graph" in nx.info(G)
  # print ("\nWorking in %s mode.." % ("CG" if is_cg else "CFG"))

  # Process as ControlFlowGraph
  caller = ""
  cg_distance = {}
  cg_distance_without_incall = {}
  bb_distance = {}
  bb_distance_without_incall = {}
  incalls = []
  func_call = {}
  if not is_cg :

    if args.cg_distance is None:
      print ("Specify file containing CG-level distance (-c).")
      exit(1)

    elif args.cg_callsites is None:
      print ("Specify file containing mapping between basic blocks and called functions (-s).")
      exit(1)

    else:

      caller = args.dot.split(".")
      caller = caller[len(caller)-2]
      print ("Loading cg_distance for function '%s'.." % caller)

      with open(args.cg_distance, 'r') as f:
        for l in f.readlines():
          s = l.strip().split(",")
          cg_distance[s[0].split(":")[0]] = int(s[1]) + 1
          cg_distance_without_incall[s[0].split(":")[0]] = int(s[2]) + 1

      if not cg_distance:
        print ("Call graph distance file is empty.")
        exit(0)

      with open(args.cg_callsites, 'r') as f:
        for l in f.readlines():
          s = l.strip().split(",")
          if find_nodes(s[0],is_cg):
            if s[1] in cg_distance:
              if s[0] in bb_distance:
                if bb_distance[s[0]] > cg_distance[s[1]]:
                  bb_distance[s[0]] = cg_distance[s[1]]
                  bb_distance_without_incall[s[0]] = cg_distance_without_incall[s[1]]
              else:
                bb_distance[s[0]] = cg_distance[s[1]]
                bb_distance_without_incall[s[0]] = cg_distance_without_incall[s[1]]
            func_call[s[0]] = s[1]

      # read indirected call site
      with open(args.cg_incallsites, 'r') as f:
        for l in f.readlines():
          s = l.strip().split(",")
          if find_nodes(s[0], is_cg):
            if s[1] in cg_distance:
              if s[0] in bb_distance:
                if bb_distance[s[0]] > cg_distance[s[1]]:
                  bb_distance[s[0]] = cg_distance[s[1]]
                  bb_distance_without_incall[s[0]] = 0
              else:
                bb_distance[s[0]] = cg_distance[s[1]]
                bb_distance_without_incall[s[0]] = 0
              incalls.append(s[0])
            func_call[s[0]] = s[1]
      
      print ("Adding target BBs (if any)..")
      with open(args.targets, "r") as f:
        for l in f.readlines ():
          s = l.strip().split("/")
          line = s[len(s) - 1]
          if find_nodes(line, is_cg):
            bb_distance[line] = 0
            print ("Added target BB %s!" % line)
            
      if not bool(bb_distance):
        exit(0)

      # reading index
      bb_index = {}
      with open(args.bb_index, "r") as f:
        for l in f.readlines():
          s = l.strip().split(",")
          bb_index[s[0]] = int(s[1])

      f_index = {}
      with open(args.f_index, "r") as f:
        for l in f.readlines():
          s = l.strip().split(",")
          for key, value in func_call.items():
            if value == s[0]:
              f_index[key] = int(s[1])

      f_out_index = {}
      with open(args.f_out_index, "r") as f:
        for l in f.readlines():
          s = l.strip().split(",")
          for key, value in func_call.items():
            if value == s[0]:
              if key not in f_out_index.keys():
                f_out_index[key] = []
              f_out_index[key].append(int(s[1]))

      # print(bb_distance)
      # print(cg_distance)
      # print(func_call)
      # print(bb_index)
  # Process as CallGraph
  else:

    bb_index = {}
    f_index = {}
    print ("Loading targets..")
    with open(args.targets, "r") as f:
      targets = []
      for line in f.readlines ():
        line = line.strip ()
        for target in find_nodes(line, is_cg):
          targets.append (target)

    if (not targets and is_cg):
      print ("No targets available")
      exit(0)

  print ("Calculating distance..")
  with open(args.out, "w") as out, open(args.names, "r") as f:
    for line in f.readlines():
      if is_cg:
        distance (line.strip(), bb_index)
      else:
        with open(args.bb_icall, "a") as icallout:
          distance (line.strip(), bb_index)
