"""
Module detecting gasleft() in loop.
"""
from typing import List, Tuple, Union

from slither.core.cfg.node import Node, NodeType
from slither.core.declarations.contract import Contract
from slither.core.declarations.solidity_variables import (
    SolidityVariableComposed,
    SolidityFunction,
)
from slither.core.expressions.expression import Expression
from slither.core.variables import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import LowLevelCall
from slither.utils.output import Output
from slither.visitors.expression.export_values import ExportValues
from slither.slithir.operations import Binary, BinaryType
import re


# Reference: https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-111
class GasLeft(AbstractDetector):
    """
    Use of gasleft() in loop
    """

    ARGUMENT = "gasleft"
    HELP = "Use of gasleft() in loop"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH
    LANGUAGE = "solidity"
    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#bad-gasleft"

    WIKI_TITLE = "Use of gasleft() in loop"
    WIKI_DESCRIPTION = "Detect the usage of gasleft() in loop."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract ContractWithDeprecatedReferences {
    // Deprecated: Change block.blockhash() -> blockhash()
    bytes32 globalBlockHash = block.blockhash(0);

    // Deprecated: Change constant -> view
    function functionWithDeprecatedThrow() public constant {
        // Deprecated: Change msg.gas -> gasleft()
        if(msg.gas == msg.value) {
            // Deprecated: Change throw -> revert()
            throw;
        }
    }

    // Deprecated: Change constant -> view
    function functionWithDeprecatedReferences() public constant {
        // Deprecated: Change sha3() -> keccak256()
        bytes32 sha3Result = sha3("test deprecated sha3 usage");

        // Deprecated: Change callcode() -> delegatecall()
        address(this).callcode();

        // Deprecated: Change suicide() -> selfdestruct()
        suicide(address(0));
    }
}
```"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Replace all uses of deprecated symbols."

    # The format for the following deprecated lists is [(detecting_signature, original_text, recommended_text)]
    DEPRECATED_SOLIDITY_VARIABLE = [
        ("gasleft()", "gasleft()", "gasleft()"),
    ]
    
    DEPRECATED_SOLIDITY_FUNCTIONS = [
        ("gasleft()", "gasleft()", "gasleft()"),
    ]
    
    DEPRECATED_NODE_TYPES = [(NodeType.THROW, "throw", "revert()")]
    DEPRECATED_LOW_LEVEL_CALLS = [("callcode", "callcode", "delegatecall")]
    
    
    def check_specific_comparison_in_string(text, var1, var2):
        # 将给定的变量名和比较运算符放入正则表达式
        pattern = fr'\b{var1}\s*(==|!=|<=|>=|<|>)\s*{var2}\b'

        # 使用re.search函数搜索文本
        match = re.search(pattern, text)

        if match:
            return True, match.group()
        else:
            return False, None


    def detect_deprecation_in_expression(
        self, expression: Expression
    ) -> List[Tuple[str, str, str]]:
        """Detects if an expression makes use of any deprecated standards.

        Returns:
            list of tuple: (detecting_signature, original_text, recommended_text)"""
        # Perform analysis on this expression
        export = ExportValues(expression)
        export_values = export.result()

        # Define our results list
        results = []

        # Check if there is usage of any deprecated solidity variables or functions
        # for dep_var in self.DEPRECATED_SOLIDITY_VARIABLE:
        #     if SolidityVariableComposed(dep_var[0]) in export_values:
        #         results.append(dep_var)
        for dep_func in self.DEPRECATED_SOLIDITY_FUNCTIONS:
            if SolidityFunction(dep_func[0]) in export_values:
                results.append(dep_func)

        return results
    

    def detect_deprecated_references_in_node(
        self, node: Node
    ) -> List[Tuple[Union[str, NodeType], str, str]]:
        """Detects if a node makes use of any deprecated standards.

        Returns:
            list of tuple: (detecting_signature, original_text, recommended_text)"""
        # Define our results list
        results: List[Tuple[Union[str, NodeType], str, str]] = []

        # If this node has an expression, we check the underlying expression.
        if node.type in [NodeType.IF, NodeType.IFLOOP]:
            if node.expression:
                results += self.detect_deprecation_in_expression(node.expression)

        return results

    def detect_deprecated_references_in_contract(
        self, contract: Contract
    ) -> List[
        Union[
            Tuple[StateVariable, List[Tuple[str, str, str]]],
            Tuple[Node, List[Tuple[Union[str, NodeType], str, str]]],
        ]
    ]:
        """Detects the usage of any deprecated built-in symbols.

        Returns:
            list of tuple: (state_variable | node, (detecting_signature, original_text, recommended_text))"""
        results: List[
            Union[
                Tuple[StateVariable, List[Tuple[str, str, str]]],
                Tuple[Node, List[Tuple[Union[str, NodeType], str, str]]],
            ]
        ] = []

        for state_variable in contract.state_variables_declared:
            if state_variable.expression:
                deprecated_results = self.detect_deprecation_in_expression(
                    state_variable.expression
                )
                if deprecated_results:
                    results.append((state_variable, deprecated_results))

        # Loop through all functions + modifiers in this contract.
        # pylint: disable=too-many-nested-blocks
        for function in contract.functions_and_modifiers_declared:
            # Loop through each node in this function.
            for node in function.nodes:
                # Detect deprecated references in the node.
                deprecated_results_node = self.detect_deprecated_references_in_node(node)
                        
                    # if isinstance(ir, LowLevelCall):
                        # for dep_llc in self.DEPRECATED_LOW_LEVEL_CALLS:
                        #     if ir.function_name == dep_llc[0]:
                        #         deprecated_results_node.append(dep_llc)

                # If we have any results from this iteration, add them to our results list.
                if deprecated_results_node:
                    print("node",node)
                    for var in node.variables_read:
                        # print(var.is_constant)
                        if var.is_constant:
                                is_comparison, comparison_string = self.check_specific_comparison_in_string(str(node.expression), var, "gasleft()()")
                                if is_comparison:
                                    # print("node",node)
                                    results.append((node, deprecated_results_node))
                    
                    # print(str(node.expression))                
                    pattern = r"gasleft\(\)\(\)\s*(==|!=|>|<|>=|<=)\s*\b\d+\b"
                    match = re.search(pattern, str(node.expression))
                    if match :
                        print("node",node)
                        results.append((node, deprecated_results_node))
                    

        return results
    


    def _detect(self) -> List[Output]:
        """Detects if an expression makes use of any deprecated standards.

        Recursively visit the calls
        Returns:
            list: {'vuln', 'filename,'contract','func', 'deprecated_references'}

        """
        results = []
        for contract in self.contracts:
            deprecated_references = self.detect_deprecated_references_in_contract(contract)
            if deprecated_references:
                for deprecated_reference in deprecated_references:
                    source_object = deprecated_reference[0]
                    deprecated_entries = deprecated_reference[1]
                    info: DETECTOR_INFO = ["Deprecated standard detected ", source_object, ":\n"]

                    for (_dep_id, original_desc, recommended_disc) in deprecated_entries:
                        info += [
                            f'\t- Usage of "{original_desc}" should be replaced with "{recommended_disc}"\n'
                        ]

                    res = self.generate_result(info)
                    results.append(res)

        return results