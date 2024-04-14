from typing import List, Dict
from slither.utils.output import Output
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.formatters.variables.unchanged_state_variables import custom_format
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.detectors.variables.unchanged_state_variables import UnchangedStateVariables


class MissingConstAddressValidation(AbstractDetector):
    """
    Constant address
    """

    ARGUMENT = "constant-address"
    HELP = "Missing Constant address Validation"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation"
    WIKI_TITLE = "Missing Constant address validation"
    WIKI_DESCRIPTION = "Detect missing Constant address validation."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract C {

  modifier onlyAdmin {
    if (msg.sender != owner) throw;
    _;
  }

  function updateOwner(address newOwner) onlyAdmin external {
    owner = newOwner;
  }
}
```
Bob calls `updateOwner` without specifying the `newOwner`, so Bob loses ownership of the contract.
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Check that the address is not zero."

    def _detect(self) -> List[Output]:
        """Detect state variables that could be constant"""
        results = {}

        unchanged_state_variables = UnchangedStateVariables(self.compilation_unit)
        unchanged_state_variables.detect_const_add()
        # unchanged_state_variables.detect()

        for variable in unchanged_state_variables.constant_candidates:
            if variable.expression is not None and str(variable.expression).startswith("address(0x"):
                # print(str(variable.canonical_name))
                # print(variable.type)
                # print(variable.expression,"exist constant address！！！")
                # print(results)
                results[variable.canonical_name] = self.generate_result(
                    [variable, " should be constant \n"]
                )

        # Order by canonical name for deterministic results
        return [results[k] for k in sorted(results)]
        # return results

    @staticmethod
    def _format(compilation_unit: SlitherCompilationUnit, result: Dict) -> None:
        custom_format(compilation_unit, result, "constant")

