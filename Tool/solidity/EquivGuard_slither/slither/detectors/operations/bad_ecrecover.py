"""
    Module detecting wrong use of ecrecover

"""
from typing import List, Tuple
import re
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
from slither.core.declarations.solidity_variables import (
    SolidityFunction,
    SolidityVariableComposed,
    SolidityVariable,
)
from slither.slithir.operations import SolidityCall
from slither.visitors.expression.export_values import ExportValues

def _ecrecover(func: Function) -> List[Node]:
    ret = set()
    for node in func.nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall) and ir.function == SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)"):
                ret.add(node)
                # print("\tecrecover:")
                # print(f"\t\t\t{ir}")
                # print("\tblocknumber_var:")
                # print(f"\t\t\t{func.parameters[1]}")
                # if is_dependent(func.parameters[1], SolidityVariableComposed("block.chainid"), func):
                #     print("\tvar_read:")
                #     ret.add(node)

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
    # for f in [f for f in contract.functions if f.contract_declarer == contract]:
    for f in contract.functions_and_modifiers_declared:
        nodes: List[Node] = _ecrecover(f)
        if nodes:
            ret.append((f, nodes))
    return ret


class BadEcrecover(AbstractDetector):

    ARGUMENT = "constChainID"
    HELP = "wrong use of ecrecover"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#const-chainid"

    WIKI_TITLE = "Const Block Number"
    WIKI_DESCRIPTION = (
        "Dwrong use of ecrecover."
    )
    WIKI_EXPLOIT_SCENARIO = """"Bob's contract relies on `block.number` for its randomness. Eve is a miner and manipulates `block.number` to exploit Bob's contract."""
    WIKI_RECOMMENDATION = "Avoid relying on the const."

    def _detect(self) -> List[Output]:
        """"""
        cret = False
        bret = False
        dret = False
        results = []
        DEPRECATED_SOLIDITY_FUNCTIONS = [
        ("chainid()", "chainid()", "chainid()"), 
        # ("chainId", "chainId", "chainId"),
        ]
        for c in self.contracts:
            for function in c.functions:
                for node in function.nodes:
                    if node.expression:
                        export = ExportValues(node.expression)
                        export_values = export.result()
                        # print(str(export_values))
                        for dep_func in DEPRECATED_SOLIDITY_FUNCTIONS:
                            if SolidityFunction(dep_func[0]) in export_values :
                                # print("chainid()",dep_func[0])
                                cret = True            
                            elif len(export_values):
                                # export_values = [str(item) for item in export_values]
                                # for item in export_values:
                                # print(node)
                                pattern = re.compile(r'.*?id.*? =.*?chain.*?', re.IGNORECASE)
                                pattern1 = re.compile(r'RETURN chainid.*?', re.IGNORECASE)
                                if pattern.search(str(node)) or pattern1.search(str(node)):
                                    # print("chainid()")
                                    print("node...",node)
                                    dret = True               
                for sv in function.slithir_variables:                
                        if  is_dependent(sv, SolidityVariableComposed("block.chainid"), c):
                            # print("block.chainid")
                            bret = True
                            
            # source = c.get_state_variable_from_name("chainId")
            # print(source)
            dangerous_blocknumber = _detect_dangerous_blocknumber(c)
            if dangerous_blocknumber:
                for (func, nodes) in dangerous_blocknumber:
                #     for sv in func.slithir_variables:                
                #         if  not is_dependent(sv, SolidityVariableComposed("block.chainid"), c):
                #             print("block.chainid",sv)
                    # print(bret,cret,dret)
                    # if (not bret and not cret and not dret):
                    # if not (bret and cret):
                    info: DETECTOR_INFO = [func, " Use constant as chainid\n"]

                    info += ["\tDangerous comparisons:\n"]

                    # sort the nodes to get deterministic results
                    nodes.sort(key=lambda x: x.node_id)

                    for node in nodes:
                        info += ["\t- ", node, "\n"]

                    res = self.generate_result(info)

                    results.append(res)
                    
        print(bret,cret,dret)
        if (not bret and not cret and not dret):      
            return results
        else:
            return []
