"""
    Module detecting operate with block.number

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


def _blocknumber(func: Function) -> List[Node]:
    ret = set()
    for node in func.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary):
                if ir.type in [
                    BinaryType.POWER,
                    BinaryType.MULTIPLICATION,
                    BinaryType.ADDITION,
                    BinaryType.SUBTRACTION,
                    BinaryType.DIVISION,
                ]:
                # if isinstance(ir, Binary) and BinaryType.return_bool(ir.type):
                    for var_read in ir.read:
                        if not isinstance(var_read, (Variable, SolidityVariable)):
                            continue
                        if is_dependent(var_read, SolidityVariableComposed("block.number"), node):
                            ret.add(node)
                            # print("\tvar_read_block:")
                            # print(f"\t\t\t{var_read}")
    return sorted(list(ret), key=lambda x: x.node_id)


def _detect_operate_blocknumber(
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


class operateBlockNumber(AbstractDetector):

    ARGUMENT = "operateBlocknumber"
    HELP = "operate with `block.number`"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#block-timestampxx"

    WIKI_TITLE = "operate with Block Number"
    WIKI_DESCRIPTION = (
        "Dangerous usage of `block.number`. `block.number` can be manipulated by miners."
    )
    WIKI_EXPLOIT_SCENARIO = """"Bob's contract relies on `block.number` for its randomness. Eve is a miner and manipulates `block.number` to exploit Bob's contract."""
    WIKI_RECOMMENDATION = "Avoid relying on `block.number`."

    def _detect(self) -> List[Output]:
        """"""
        results = []

        for c in self.contracts:
            dangerous_blocknumber = _detect_operate_blocknumber(c)
            for (func, nodes) in dangerous_blocknumber:

                info: DETECTOR_INFO = [func, " operate with Block Number\n"]

                info += ["\tDangerous compute:\n"]

                # sort the nodes to get deterministic results
                nodes.sort(key=lambda x: x.node_id)

                for node in nodes:
                    info += ["\t- ", node, "\n"]

                res = self.generate_result(info)

                results.append(res)

        return results
