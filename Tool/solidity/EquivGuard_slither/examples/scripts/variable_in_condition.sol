contract Contract{

    uint a;

    function condition() public{
        if(a==0){

        }
    }

    function call_require() public{
        require(a==0);
    }
    
    function read_and_write() public{
        a = a + 1;
    }

}

// SPDX-License-Identifier: MIT
// pragma solidity ^0.8.0;

// contract Vul2 {

//     event GasLeft(uint256 gas, uint index);
//     struct Payee {
//         address addr;
//         uint256 value;
//     }

//     Payee[500] payees;
//     uint256 nextPayeeIndex;

//     function payOut() public returns (uint) {
//         uint256 i = nextPayeeIndex;
//         while (i < payees.length && gasleft() > 400000) {
//             payees[i].value = 0;
//             payees[i].value=payees[i].value+1;
//             i++;
//         }
//         nextPayeeIndex = i;

//         emit GasLeft(gasleft(), nextPayeeIndex);

//         return nextPayeeIndex;
//     }

//     function getNextPayeeIndexValue() public view returns (uint256) {
//         return nextPayeeIndex;
//     }

// }