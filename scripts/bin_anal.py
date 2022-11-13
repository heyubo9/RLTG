import angr
import argparse
from argparse import ArgumentTypeError as ArgTypeErr
from pathlib import Path
import os
import networkx as nx
from networkx.drawing.nx_pydot import write_dot

def merge_callgraphs(dots, outfilepath):
    #print(f"({STEP}) Integrating several call-graphs into one.")
    G = nx.DiGraph()
    for dot in dots:
        G.update(nx.DiGraph(nx.drawing.nx_pydot.read_dot(dot)))
    with outfilepath.open('w') as f:
        nx.drawing.nx_pydot.write_dot(G, f)

def binary_analysis(args):
    p = angr.Project(args.binaries_directory / args.fuzzer_name, load_options={'auto_load_libs':True})

    cfg = p.analyses.CFGFast()
    print("Generate CFG Done!")

    bbcalls = args.temporary_directory / "BBcalls.txt"
    bbnames = args.temporary_directory / "BBnames.txt"
    fnames = args.temporary_directory / "Fnames.txt"
    ftarget = args.temporary_directory / "Ftargets.txt"
    bbtarget = args.temporary_directory / "BBtargets.txt"
    dotfiledir = args.temporary_directory / "dot-files"
    cgfile = dotfiledir / "callgraph.dot"
    distancefile = args.temporary_directory / "distance.cfg.txt"

    # caculating callgraph distance
    callgraph_distance = args.temporary_directory / "callgraph.distance.txt"

    # 读取符号表
    f_ftarget = open(ftarget, "w")
    f_fname = open(fnames, "w")
    f_bbname = open(bbnames, "w")
    f_bbcall = open(bbcalls, "w")
    distance_file = open(distancefile, "w")
    f_bbtarget = open(bbtarget, "r")

    bb_target = []
    f_target = []
    cg_distance = {}

    # construct callgraph
    cg = cfg.kb.callgraph
    write_dot(cg, cgfile)

    func_list = cfg.kb.functions
    bbtarget_list = f_bbtarget.read().splitlines()
    for bb in bbtarget_list:
        bb_target.append(int(bb, 16))

    # construct fnames, ftarget
    for addr, func in func_list.items():
        funcname = func.name
        func_addr = p.loader.main_object.get_symbol(funcname)

        if func_addr is None:
            continue
        
        # construct fnames
        f_fname.write("%s\n"%funcname)
        offset = func_addr.rebased_addr - func_addr.relative_addr

        # construct ftargets
        bb_list = func.blocks
        for bb in bb_list:
            bb_addr = bb.addr - offset
            if bb_addr in bb_target:
                f_ftarget.write("%s\n"%(funcname))
                f_target.append(func_addr.rebased_addr)
    
    # construct callgraph distance
    print("caculating callgraph distance")
    for addr, func in func_list.items():
        d = 0.0
        i = 0
        distance = -1
        funcname = func.name
        
        func_addr = p.loader.main_object.get_symbol(funcname)

        if func_addr is None:
            continue

        for t in f_target:
            # print("%s(%d) to %s(%d)"%(func.name, func_addr.rebased_addr, cfg.kb.functions[t].name, t))
            try:
                shortest = nx.dijkstra_path_length(cg, func_addr.rebased_addr, t)
                d += 1.0 / (1.0 + shortest)
                i += 1
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
        if d != 0 and (distance == -1 or distance > i / d) :
            distance = i / d
            cg_distance[addr] = distance

    # print("call graph distance is :")
    # for func, distance in cg_distance.items():
    #     if distance != -1:
    #         print("%s:%s"%(func, distance))

    # construct bbcalls and bbnames
    print("caculating control-flow distance")
    for addr, func in func_list.items():
        bb_distance = {}

        funcname = func.name
        func_addr = p.loader.main_object.get_symbol(funcname)

        if func_addr is None:
            continue
        
        offset = func_addr.rebased_addr - func_addr.relative_addr

        # construct bbnames
        bb_list = func.blocks
        for bb in bb_list:
            f_bbname.write("%#x\n"%(bb.addr - offset))
            bb_addr = bb.addr - offset
            if bb_addr in bb_target:
                bb_distance[bb] = 0

        # construct bbcalls
        call_sites = func.get_call_sites()
        for call_site in call_sites:
            try:
                target = func.get_call_target(call_site)
                l = "%#x,%s\n"%(call_site - offset, cfg.kb.functions[target].name)
                f_bbcall.write(l)

                bb_node = cfg.model.get_any_node(call_site)
                if target in cg_distance:
                    if bb_node in bb_distance:
                        if bb_distance[bb_node] > cg_distance[target]:
                            bb_distance[bb_node] = cg_distance[target]
                    else:
                        bb_distance[bb_node] = cg_distance[target]
            except KeyError:
                continue

        
        # construct dotfiles
        dotfile = dotfiledir / f"cfg.{funcname}.dot"
        tg = func.transition_graph
        write_dot(tg, dotfile)

        # caculating cfg distance
        bb_list = func.blocks
        for bb in bb_list:
            d = 0.0
            i = 0
            distance = -1

            for t, bb_d in bb_distance.items():
                di = 0.0
                ii = 0
                # print("%#x to %#x"%(bb.addr, t.addr))
                try:
                    shortest = nx.dijkstra_path_length(tg, bb.addr, t.addr)
                    di += 1.0 / (1.0 + 10 * bb_d + shortest)
                    ii += 1
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                if ii != 0:
                    d += di / ii
                    i += 1

            if d != 0 and (distance == -1 or distance > i / d) :
                distance = i / d

            if distance != -1:
                distance_file.write("%#x,%s\n"%(bb.addr - offset, str(distance)))

    f_fname.close()
    f_bbname.close()
    f_bbcall.close()
    f_bbtarget.close()
    f_ftarget.close()
    distance_file.close()

# -- Argparse --
def is_path_to_dir(path):
    """Returns Path object when path is an existing directory"""
    p = Path(path)
    if not p.exists():
        raise ArgTypeErr("path doesn't exist")
    if not p.is_dir():
        raise ArgTypeErr("not a directory")
    return p
# ----

def main():
    global STEP
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries_directory", metavar="binaries_directory",
                        type=is_path_to_dir,
                        help="Directory where binaries of 'subject' are "
                             "located")
    parser.add_argument("temporary_directory", metavar="temporary-directory",
                        type=is_path_to_dir,
                        help="Directory where dot files and target files are "
                             "located")
    parser.add_argument("fuzzer_name", metavar="fuzzer-name",
                        nargs='?',
                        help="Name of fuzzer binary")
    args = parser.parse_args()
    binary_analysis(args)



if __name__ == '__main__':
    main()
