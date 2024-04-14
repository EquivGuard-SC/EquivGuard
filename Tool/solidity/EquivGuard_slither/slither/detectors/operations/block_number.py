"""
    Module detecting dangerous use of block.number

"""
from typing import List, Tuple

from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.cfg.node import Node
from slither.core.declarations import Function, Contract, FunctionContract
from slither.core.declarations.solidity_variables import (
    SolidityVariableComposed,
    SolidityVariable,
)
from slither.core.variables import Variable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output
from slither.slithir.variables import Constant
from slither.detectors.variables.unchanged_state_variables import UnchangedStateVariables
from slither.visitors.expression.export_values import ExportValues
import re

def _blocknumber(func: Function) -> List[Node]:
    ret = set()
    for node in func.nodes:
        # for var in node.variables_read:
        #     # print("\tvar:")
        #     # print(f"\t\t\t{var}")
        #     if is_dependent(var, SolidityVariableComposed("block.number"), node):
        #         print("\tblocknumber_var:")
        #         print(f"\t\t\t{var}")
        #         ret.add(node)
        for ir in node.irs:
            # print("\tir:")
            # print(f"\t\t\t{ir}")
            if isinstance(ir, Binary) and BinaryType.return_bool(ir.type):
                for var_read in ir.read:
                    # print("\tvar_read:")
                    # print(f"\t\t\t{var_read}")
                    if not isinstance(var_read, (Variable, SolidityVariable)):
                        continue
                    if is_dependent(var_read, SolidityVariableComposed("block.number"), node):
                        ret.add(node)
                        # print("\tvar_read_block:")
                        # print(f"\t\t\t{var_read}")
    return sorted(list(ret), key=lambda x: x.node_id)


def _detect_dangerous_blocknumber(
    contract: Contract,
) -> List[Tuple[FunctionContract, List[Node]]]:
    """
    Args:
        contract (Contract)
    Returns:
        list((Function), (list (Node)))
    """
    ret = []
    for f in [f for f in contract.functions if f.contract_declarer == contract]:
        nodes: List[Node] = _blocknumber(f)
        if nodes:
            ret.append((f, nodes))
    return ret


def check_specific_comparison_in_string(text, var1, var2):
    # 将给定的变量名和比较运算符放入正则表达式
    pattern = fr'\b{var1}\s*(==|!=|<=|>=|<|>)\s*{var2}\b'

    # 使用re.search函数搜索文本
    match = re.search(pattern, text)

    if match:
        return True, match.group()
    else:
        return False, None


class BlockNumber(AbstractDetector):

    ARGUMENT = "constBlocknumber"
    HELP = "Dangerous usage of `block.number`"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#const_blocknumber"

    WIKI_TITLE = "Const Block Number"
    WIKI_DESCRIPTION = (
        "Dangerous usage of `block.number`. `block.number` can be manipulated by miners."
    )
    WIKI_EXPLOIT_SCENARIO = """"Bob's contract relies on `block.number` for its randomness. Eve is a miner and manipulates `block.number` to exploit Bob's contract."""
    WIKI_RECOMMENDATION = "Avoid relying on `block.number`."

    def _detect(self) -> List[Output]:
        """"""
        results = []
        
        unchanged_state_variables = UnchangedStateVariables(self.compilation_unit)
        # unchanged_state_variables.detect_const_add()
        unchanged_state_variables.detect()

        # for variable in unchanged_state_variables.constant_candidates:
        #     print("variable",variable,type(variable))   
            # //比较variable是否存在node.expression中

        for c in self.contracts:
            dangerous_blocknumber = _detect_dangerous_blocknumber(c)
            for (func, nodes) in dangerous_blocknumber:
                for node in nodes:
                    export = ExportValues(node.expression)
                    export_values = export.result()
                    # print("blocknumber",node.expression)
                    for ir in node.irs:
                        for var_read in ir.read:
                            if is_dependent(var_read, SolidityVariableComposed("block.number"), node):
                                # print("\tvar_read_block:")
                                # print(f"\t\t\t{var_read}")    
                                for variable in unchanged_state_variables.constant_candidates:
                                    # print("variable",variable)  
                                    is_comparison, comparison_string = check_specific_comparison_in_string(str(node.expression), var_read, variable)
                                    if is_comparison:
                                        # print(f"找到了比较语句: {comparison_string}")
                                    # else:
                                    #     print(f"在给定文本中没有找到比较语句.")
                                    # if variable in export_values:
                                    #     # print("variable",variable)   

                                        info: DETECTOR_INFO = [func, " uses a constant for blocknumber comparisons\n"]

                                        info += ["\tDangerous comparisons:\n"]

                                        # sort the nodes to get deterministic results
                                        nodes.sort(key=lambda x: x.node_id)

                                        for node in nodes:
                                            info += ["\t- ", node, "\n"]

                                        res = self.generate_result(info)

                                        results.append(res)

        return results
